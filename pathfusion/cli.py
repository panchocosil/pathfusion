from __future__ import annotations

from contextlib import nullcontext
import logging
import re
from pathlib import Path
from typing import Annotated
from urllib.parse import urljoin, urlparse

import typer
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from pathfusion.analyzers.baseline import build_baseline_profile, compare_to_baseline
from pathfusion.analyzers.correlate import choose_next_targets, finding_from_url
from pathfusion.analyzers.normalize import group_by_host, normalize_host, normalize_targets
from pathfusion.analyzers.scoring import apply_scores
from pathfusion.config import load_config
from pathfusion.models import Finding, OutputFormat, ScanConfig, SourceTool
from pathfusion.reports.csv_report import write_csv
from pathfusion.reports.json_report import write_json, write_jsonl
from pathfusion.reports.markdown_report import write_markdown
from pathfusion.runners.dirsearch import DirsearchRunner
from pathfusion.runners.feroxbuster import FeroxbusterRunner
from pathfusion.runners.katana import KatanaRunner
from pathfusion.storage.store import FindingStore
from pathfusion.utils import configure_logging, create_workdir, run_command

app = typer.Typer(help="PathFusion - intelligence-driven web path discovery for authorized testing")
console = Console()

INSTALL_HINTS = {
    "katana": "Install katana: go install github.com/projectdiscovery/katana/cmd/katana@latest",
    "dirsearch": "Install dirsearch: pip install dirsearch or clone from github.com/maurosoria/dirsearch",
    "feroxbuster": "Install feroxbuster: cargo install feroxbuster",
}


def _split_extensions(value: str | None, fallback: list[str]) -> list[str]:
    if not value:
        return sorted(set(fallback))
    parts = [item.strip().lower().lstrip(".") for item in value.split(",") if item.strip()]
    return sorted(set(parts))


def _parse_int(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        match = re.search(r"\d+", value)
        return int(match.group(0)) if match else None
    return None


def _parse_size_bytes(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        raw = value.strip()
        if raw.isdigit():
            return int(raw)
        match = re.search(r"(\d+(?:\.\d+)?)\s*([KMG]?B)\b", raw, re.IGNORECASE)
        if not match:
            return _parse_int(raw)
        amount = float(match.group(1))
        unit = match.group(2).upper()
        multiplier = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3}.get(unit, 1)
        return int(amount * multiplier)
    return None


def _is_noisy_status_for_bruteforce(status_code: int | None) -> bool:
    if status_code is None:
        return False
    return status_code in {400, 404, 405, 410, 500, 501, 502, 503, 504}


def _print_preflight(statuses: dict[str, tuple[bool, str]]) -> None:
    table = Table(title="Dependency Check")
    table.add_column("Tool")
    table.add_column("Status")
    table.add_column("Detail")
    for tool, (ok, detail) in statuses.items():
        table.add_row(tool, "OK" if ok else "MISSING", detail)
    console.print(table)


def _phase_header(title: str, interactive: bool) -> None:
    if interactive:
        console.rule(f"[bold cyan]{title}")


def _expand_scope_hosts(hosts: set[str]) -> set[str]:
    expanded: set[str] = set()
    for host in hosts:
        host = normalize_host(host)
        expanded.add(host)
        if host.startswith("www."):
            expanded.add(host[4:])
        else:
            expanded.add(f"www.{host}")
    return expanded


def _check_tool_callable(binary: str) -> tuple[bool, str]:
    probe = run_command([binary, "-h"], timeout=20)
    if probe.returncode == 127:
        return False, probe.stderr
    combined = f"{probe.stdout}\n{probe.stderr}"
    if "traceback (most recent call last)" in combined.lower():
        lines = [line.strip() for line in combined.splitlines() if line.strip()]
        detail = lines[-1] if lines else "python traceback"
        return False, f"broken installation: {detail}"
    return True, f"callable (exit={probe.returncode})"


def _preflight(tool_map: dict[str, str]) -> tuple[bool, dict[str, tuple[bool, str]]]:
    statuses: dict[str, tuple[bool, str]] = {}
    all_ok = True
    for name, binary in tool_map.items():
        ok, detail = _check_tool_callable(binary)
        statuses[name] = (ok, f"{binary}: {detail}")
        if not ok:
            all_ok = False
    return all_ok, statuses


def _to_dirsearch_findings(records: list[dict], in_scope_hosts: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    for record in records:
        target = str(record.get("_target", ""))
        url = record.get("url") or record.get("location") or record.get("target")
        if not url:
            path = record.get("path") or record.get("uri")
            if path and target:
                url = urljoin(target if target.endswith("/") else f"{target}/", str(path).lstrip("/"))
        if not isinstance(url, str) or not url.startswith(("http://", "https://")):
            continue
        host = normalize_host(urlparse(url).hostname or "")
        if host not in in_scope_hosts:
            continue
        status = _parse_int(record.get("status") or record.get("status_code"))
        length = _parse_size_bytes(
            record.get("content-length")
            or record.get("content_length")
            or record.get("length")
            or record.get("size")
        )
        finding = finding_from_url(url, SourceTool.DIRSEARCH, status_code=status, content_length=length)
        finding.meta["raw_dirsearch"] = {k: v for k, v in record.items() if k != "_target"}
        findings.append(finding)
    return findings


def _to_ferox_findings(records: list[dict], in_scope_hosts: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    for record in records:
        url = record.get("url") or record.get("request") or record.get("location")
        if not isinstance(url, str) or not url.startswith(("http://", "https://")):
            continue
        host = normalize_host(urlparse(url).hostname or "")
        if host not in in_scope_hosts:
            continue
        status = _parse_int(record.get("status") or record.get("status_code"))
        length = _parse_size_bytes(record.get("content_length") or record.get("content-length") or record.get("size"))
        finding = finding_from_url(url, SourceTool.FEROXBUSTER, status_code=status, content_length=length)
        finding.meta["raw_feroxbuster"] = {k: v for k, v in record.items() if k != "_target"}
        findings.append(finding)
    return findings


def _to_katana_findings(records: list[dict], in_scope_hosts: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    for record in records:
        url = record.get("url")
        if not isinstance(url, str) or not url.startswith(("http://", "https://")):
            continue
        host = normalize_host(urlparse(url).hostname or "")
        if host not in in_scope_hosts:
            continue
        finding = finding_from_url(url, SourceTool.KATANA)
        finding.meta["raw_katana"] = record
        findings.append(finding)
    return findings


def _print_top_findings(findings: list[Finding], limit: int = 25) -> None:
    table = Table(title="Top PathFusion Findings")
    table.add_column("Score", justify="right")
    table.add_column("Status", justify="right")
    table.add_column("URL")
    table.add_column("Sources")
    table.add_column("Tags")

    for finding in sorted(findings, key=lambda item: item.score, reverse=True)[:limit]:
        status = str(finding.status_code) if finding.status_code is not None else "-"
        sources = ",".join(sorted(source.value for source in finding.sources))
        tags = ",".join(sorted(finding.tags))
        table.add_row(f"{finding.score:.2f}", status, finding.url, sources, tags)
    console.print(table)


def _print_live_findings(
    findings: list[Finding],
    source: SourceTool,
    seen: set[str],
    enabled: bool,
) -> None:
    if not enabled:
        return
    for finding in findings:
        if finding.normalized_url in seen:
            continue
        seen.add(finding.normalized_url)
        status = str(finding.status_code) if finding.status_code is not None else "-"
        console.print(f"[green][{source.value}][/green] {status} {finding.url}")


def _write_outputs(
    findings: list[Finding],
    output_path: Path | None,
    output_format: OutputFormat,
    json_shortcut: Path | None,
    target_count: int,
    logger: logging.Logger,
) -> None:
    if json_shortcut:
        write_json(findings, json_shortcut)
        logger.info("JSON written to %s", json_shortcut)

    if not output_path:
        return

    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_format == OutputFormat.JSON:
        write_json(findings, output_path)
    elif output_format == OutputFormat.JSONL:
        write_jsonl(findings, output_path)
    elif output_format == OutputFormat.CSV:
        write_csv(findings, output_path)
    elif output_format == OutputFormat.MARKDOWN:
        write_markdown(findings, output_path, target_count=target_count)
    logger.info("Report written to %s", output_path)


def _build_scan_config(
    url: list[str],
    list_file: Path | None,
    proxy: str | None,
    insecure: bool,
    follow_redirects: bool,
    katana_depth: int,
    katana_concurrency: int,
    wordlist: Path | None,
    extensions: str | None,
    enable_ferox: bool,
    ferox_depth: int,
    threads: int,
    dirsearch_timeout: int,
    dirsearch_headers: list[str],
    dirsearch_full_url: bool,
    dirsearch_random_agent: bool,
    baseline_samples: int,
    baseline_timeout: int,
    skip_baseline: bool,
    output: Path | None,
    output_format: OutputFormat,
    second_pass: bool,
    max_hosts: int | None,
    check: bool,
    verbose: bool,
    live_findings: bool,
    config: Path | None,
    defaults: list[str],
) -> ScanConfig:
    return ScanConfig(
        urls=url,
        list_file=list_file,
        proxy=proxy,
        insecure=insecure,
        follow_redirects=follow_redirects,
        katana_depth=katana_depth,
        katana_concurrency=katana_concurrency,
        wordlist=wordlist,
        extensions=_split_extensions(extensions, defaults),
        enable_ferox=enable_ferox,
        ferox_depth=ferox_depth,
        threads=threads,
        dirsearch_timeout=dirsearch_timeout,
        dirsearch_headers=dirsearch_headers,
        dirsearch_full_url=dirsearch_full_url,
        dirsearch_random_agent=dirsearch_random_agent,
        baseline_samples=baseline_samples,
        baseline_timeout=baseline_timeout,
        skip_baseline=skip_baseline,
        output_path=output,
        output_format=output_format,
        second_pass=second_pass,
        max_hosts=max_hosts,
        check_only=check,
        verbose=verbose,
        live_findings=live_findings,
        config_path=config,
    )


@app.command()
def scan(
    url: Annotated[list[str], typer.Option("-u", "--url", help="Target URL (repeatable)")] = [],
    list_file: Annotated[Path | None, typer.Option("-l", "--list", help="File with target URLs")] = None,
    proxy: Annotated[str | None, typer.Option("--proxy", help="HTTP proxy URL")] = None,
    insecure: Annotated[
        bool,
        typer.Option("--insecure/--secure", help="Disable/enable TLS certificate verification"),
    ] = True,
    follow_redirects: Annotated[
        bool,
        typer.Option("--follow-redirects/--no-follow-redirects", help="Follow HTTP redirects during scanning"),
    ] = False,
    katana_depth: Annotated[int, typer.Option("--katana-depth", help="Katana crawl depth")] = 3,
    katana_concurrency: Annotated[int, typer.Option("--katana-concurrency", help="Katana concurrency")] = 10,
    wordlist: Annotated[Path | None, typer.Option("--wordlist", help="Dirsearch wordlist path")] = None,
    extensions: Annotated[str | None, typer.Option("--extensions", help="Comma-separated extensions")] = None,
    enable_ferox: Annotated[bool, typer.Option("--enable-ferox", help="Enable feroxbuster stage")] = False,
    ferox_depth: Annotated[int, typer.Option("--ferox-depth", help="Ferox recursion depth")] = 3,
    threads: Annotated[int, typer.Option("--threads", help="Worker threads for brute-force tools")] = 30,
    dirsearch_timeout: Annotated[int, typer.Option("--dirsearch-timeout", min=1, help="Dirsearch request timeout (seconds)")] = 10,
    header: Annotated[list[str], typer.Option("--header", "-H", help="Custom header for dirsearch (repeatable)")] = [],
    dirsearch_full_url: Annotated[
        bool,
        typer.Option("--dirsearch-full-url/--no-dirsearch-full-url", help="Use dirsearch --full-url"),
    ] = True,
    dirsearch_random_agent: Annotated[
        bool,
        typer.Option("--dirsearch-random-agent/--no-dirsearch-random-agent", help="Use dirsearch random user agent"),
    ] = True,
    baseline_samples: Annotated[int, typer.Option("--baseline-samples", min=1, help="Baseline probes per host")] = 3,
    baseline_timeout: Annotated[int, typer.Option("--baseline-timeout", min=1, help="Baseline HTTP timeout (seconds)")] = 10,
    skip_baseline: Annotated[bool, typer.Option("--skip-baseline", help="Skip baseline profiling phase")] = False,
    output: Annotated[Path | None, typer.Option("--output", help="Output report path")] = None,
    output_format: Annotated[OutputFormat, typer.Option("--output-format", help="Output format")] = OutputFormat.MARKDOWN,
    second_pass: Annotated[bool, typer.Option("--second-pass", help="Enable second katana pass") ] = False,
    max_hosts: Annotated[int | None, typer.Option("--max-hosts", help="Max distinct hosts to scan")] = None,
    check: Annotated[bool, typer.Option("--check", help="Check dependencies and exit")] = False,
    verbose: Annotated[bool, typer.Option("--verbose", help="Verbose logging")] = False,
    live_findings: Annotated[
        bool,
        typer.Option("--live-findings/--no-live-findings", help="Show discovered URLs in real time"),
    ] = True,
    interactive: Annotated[
        bool,
        typer.Option("--interactive/--no-interactive", help="Show interactive phase/progress UI"),
    ] = True,
    config: Annotated[Path | None, typer.Option("--config", help="PathFusion TOML config")] = None,
    json_output: Annotated[Path | None, typer.Option("--json", help="Shortcut JSON output path")] = None,
) -> None:
    """Run the PathFusion multi-phase scan pipeline."""

    logger = configure_logging(verbose)
    app_config = load_config(config)

    proxy_value = proxy if proxy is not None else app_config.default_proxy
    insecure_value = insecure
    selected_wordlist = wordlist
    if selected_wordlist is None and app_config.default_wordlists:
        selected_wordlist = Path(app_config.default_wordlists[0])

    scan_config = _build_scan_config(
        url=url,
        list_file=list_file,
        proxy=proxy_value,
        insecure=insecure_value,
        follow_redirects=follow_redirects,
        katana_depth=katana_depth,
        katana_concurrency=katana_concurrency,
        wordlist=selected_wordlist,
        extensions=extensions,
        enable_ferox=enable_ferox,
        ferox_depth=ferox_depth,
        threads=threads,
        dirsearch_timeout=dirsearch_timeout,
        dirsearch_headers=header,
        dirsearch_full_url=dirsearch_full_url,
        dirsearch_random_agent=dirsearch_random_agent,
        baseline_samples=baseline_samples,
        baseline_timeout=baseline_timeout,
        skip_baseline=skip_baseline,
        output=output,
        output_format=output_format,
        second_pass=second_pass,
        max_hosts=max_hosts,
        check=check,
        verbose=verbose,
        live_findings=live_findings,
        config=config,
        defaults=app_config.default_extensions,
    )

    required_tools = {
        "katana": app_config.tools.katana,
        "dirsearch": app_config.tools.dirsearch,
    }
    if scan_config.enable_ferox:
        required_tools["feroxbuster"] = app_config.tools.feroxbuster

    ok, statuses = _preflight(required_tools)
    _print_preflight(statuses)

    if scan_config.check_only:
        if not ok:
            for tool, (is_ok, _) in statuses.items():
                if not is_ok and tool in INSTALL_HINTS:
                    console.print(INSTALL_HINTS[tool])
            raise typer.Exit(code=1)
        raise typer.Exit(code=0)

    if not ok:
        for tool, (is_ok, _) in statuses.items():
            if not is_ok and tool in INSTALL_HINTS:
                logger.error(INSTALL_HINTS[tool])
        raise typer.Exit(code=2)

    normalized_targets = normalize_targets(
        urls=scan_config.urls,
        list_file=scan_config.list_file,
        max_hosts=scan_config.max_hosts,
        allow_patterns=app_config.host_allow_patterns,
        deny_patterns=app_config.host_deny_patterns,
    )
    if not normalized_targets:
        logger.error("No valid targets provided after normalization and scope filtering")
        raise typer.Exit(code=2)

    grouped_targets = group_by_host(normalized_targets)
    in_scope_hosts = _expand_scope_hosts(set(grouped_targets))

    _phase_header("Phase 1/8 - Input Normalization", interactive)
    logger.info("Targets in scope: %d hosts / %d URLs", len(grouped_targets), len(normalized_targets))

    workdir = create_workdir()
    logger.info("Workdir: %s", workdir)

    store = FindingStore()
    live_seen: set[str] = set()

    # Phase 2: Katana discovery
    _phase_header("Phase 2/8 - Katana Discovery", interactive)
    katana_dir = workdir / "phase2_katana"
    katana_dir.mkdir(parents=True, exist_ok=True)
    katana_runner = KatanaRunner(app_config.tools.katana, logger)
    katana_status_ctx = console.status("[bold cyan]Running katana...", spinner="dots") if interactive else nullcontext()
    with katana_status_ctx:
        katana_records, _ = katana_runner.run(
            targets=normalized_targets,
            depth=scan_config.katana_depth,
            concurrency=scan_config.katana_concurrency,
            proxy=scan_config.proxy,
            insecure=scan_config.insecure,
            follow_redirects=scan_config.follow_redirects,
            workdir=katana_dir,
        )
    katana_findings = _to_katana_findings(katana_records, in_scope_hosts)
    store.add_many(katana_findings)
    _print_live_findings(katana_findings, SourceTool.KATANA, live_seen, scan_config.live_findings)
    logger.info("Katana findings (normalized): %d", len(katana_findings))
    if katana_records and not katana_findings:
        logger.warning("Katana produced %d records but none were in current scope host set", len(katana_records))

    # Phase 4 baseline
    baseline_profiles = {}
    if scan_config.skip_baseline:
        _phase_header("Phase 4/8 - Baseline Profiling (Skipped)", interactive)
        logger.info("Baseline phase skipped by user option")
    else:
        _phase_header("Phase 4/8 - Baseline Profiling", interactive)
        baseline_hosts = list(grouped_targets.items())
        if interactive:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("{task.completed}/{task.total}"),
                TimeElapsedColumn(),
                console=console,
                transient=True,
            ) as progress:
                task = progress.add_task("Baseline probes", total=len(baseline_hosts))
                for host, urls in baseline_hosts:
                    progress.update(task, description=f"Baseline {host}")
                    baseline_profiles[host] = build_baseline_profile(
                        urls[0],
                        insecure=scan_config.insecure,
                        follow_redirects=scan_config.follow_redirects,
                        proxy=scan_config.proxy,
                        samples=scan_config.baseline_samples,
                        timeout=scan_config.baseline_timeout,
                        logger=logger,
                    )
                    progress.advance(task)
        else:
            baseline_profiles = {
                host: build_baseline_profile(
                    urls[0],
                    insecure=scan_config.insecure,
                    follow_redirects=scan_config.follow_redirects,
                    proxy=scan_config.proxy,
                    samples=scan_config.baseline_samples,
                    timeout=scan_config.baseline_timeout,
                    logger=logger,
                )
                for host, urls in grouped_targets.items()
            }

    apply_scores(store.all(), app_config.weights)

    # Phase 5 intelligent dirsearch targeting
    _phase_header("Phase 5/8 - Dirsearch Expansion", interactive)
    plan = choose_next_targets(
        findings=store.all(),
        seed_targets=grouped_targets,
        max_dirsearch_paths_per_host=app_config.max_dirsearch_paths_per_host,
        max_ferox_paths_per_host=app_config.max_ferox_paths_per_host,
        ferox_score_threshold=app_config.ferox_score_threshold,
        default_extensions=scan_config.extensions,
    )

    dirsearch_runner = DirsearchRunner(app_config.tools.dirsearch, logger)
    phase5_dir = workdir / "phase5_dirsearch"
    phase5_dir.mkdir(parents=True, exist_ok=True)

    dirsearch_hosts = list(plan.dirsearch_targets.items())
    if interactive:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("Dirsearch hosts", total=len(dirsearch_hosts))
            for host, targets in dirsearch_hosts:
                progress.update(task, description=f"Dirsearch {host} ({len(targets)} targets)")
                host_dir = phase5_dir / host
                host_dir.mkdir(parents=True, exist_ok=True)
                extensions_for_host = plan.extensions_by_host.get(host, scan_config.extensions)
                records, _ = dirsearch_runner.run(
                    targets=targets,
                    threads=scan_config.threads,
                    wordlist=scan_config.wordlist,
                    extensions=extensions_for_host,
                    request_timeout=scan_config.dirsearch_timeout,
                    headers=scan_config.dirsearch_headers,
                    full_url=scan_config.dirsearch_full_url,
                    random_agent=scan_config.dirsearch_random_agent,
                    proxy=scan_config.proxy,
                    insecure=scan_config.insecure,
                    follow_redirects=scan_config.follow_redirects,
                    recurse=not app_config.selective_recursion,
                    workdir=host_dir,
                )
                dir_findings = _to_dirsearch_findings(records, in_scope_hosts)
                store.add_many(dir_findings)
                _print_live_findings(dir_findings, SourceTool.DIRSEARCH, live_seen, scan_config.live_findings)
                logger.info("Dirsearch host=%s findings=%d", host, len(dir_findings))
                progress.advance(task)
    else:
        for host, targets in dirsearch_hosts:
            host_dir = phase5_dir / host
            host_dir.mkdir(parents=True, exist_ok=True)
            extensions_for_host = plan.extensions_by_host.get(host, scan_config.extensions)
            records, _ = dirsearch_runner.run(
                targets=targets,
                threads=scan_config.threads,
                wordlist=scan_config.wordlist,
                extensions=extensions_for_host,
                request_timeout=scan_config.dirsearch_timeout,
                headers=scan_config.dirsearch_headers,
                full_url=scan_config.dirsearch_full_url,
                random_agent=scan_config.dirsearch_random_agent,
                proxy=scan_config.proxy,
                insecure=scan_config.insecure,
                follow_redirects=scan_config.follow_redirects,
                recurse=not app_config.selective_recursion,
                workdir=host_dir,
            )
            dir_findings = _to_dirsearch_findings(records, in_scope_hosts)
            store.add_many(dir_findings)
            _print_live_findings(dir_findings, SourceTool.DIRSEARCH, live_seen, scan_config.live_findings)
            logger.info("Dirsearch host=%s findings=%d", host, len(dir_findings))

    # Optional phase 6 feroxbuster
    if scan_config.enable_ferox:
        _phase_header("Phase 6/8 - Feroxbuster Recursion", interactive)
        apply_scores(store.all(), app_config.weights)
        plan = choose_next_targets(
            findings=store.all(),
            seed_targets=grouped_targets,
            max_dirsearch_paths_per_host=app_config.max_dirsearch_paths_per_host,
            max_ferox_paths_per_host=app_config.max_ferox_paths_per_host,
            ferox_score_threshold=app_config.ferox_score_threshold,
            default_extensions=scan_config.extensions,
        )
        ferox_runner = FeroxbusterRunner(app_config.tools.feroxbuster, logger)
        phase6_dir = workdir / "phase6_feroxbuster"
        phase6_dir.mkdir(parents=True, exist_ok=True)

        ferox_hosts = [(host, targets) for host, targets in plan.ferox_targets.items() if targets]
        if interactive:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("{task.completed}/{task.total}"),
                TimeElapsedColumn(),
                console=console,
                transient=True,
            ) as progress:
                task = progress.add_task("Ferox hosts", total=max(1, len(ferox_hosts)))
                if not ferox_hosts:
                    progress.update(task, description="Ferox skipped (no high-value paths)", completed=1)
                for host, targets in ferox_hosts:
                    progress.update(task, description=f"Ferox {host} ({len(targets)} targets)")
                    host_dir = phase6_dir / host
                    host_dir.mkdir(parents=True, exist_ok=True)
                    extensions_for_host = plan.extensions_by_host.get(host, scan_config.extensions)
                    records, _ = ferox_runner.run(
                        targets=targets,
                        depth=scan_config.ferox_depth,
                        threads=scan_config.threads,
                        proxy=scan_config.proxy,
                        insecure=scan_config.insecure,
                        follow_redirects=scan_config.follow_redirects,
                        extensions=extensions_for_host,
                        workdir=host_dir,
                    )
                    ferox_findings = _to_ferox_findings(records, in_scope_hosts)
                    store.add_many(ferox_findings)
                    _print_live_findings(ferox_findings, SourceTool.FEROXBUSTER, live_seen, scan_config.live_findings)
                    logger.info("Feroxbuster host=%s findings=%d", host, len(ferox_findings))
                    progress.advance(task)
        else:
            for host, targets in ferox_hosts:
                host_dir = phase6_dir / host
                host_dir.mkdir(parents=True, exist_ok=True)
                extensions_for_host = plan.extensions_by_host.get(host, scan_config.extensions)
                records, _ = ferox_runner.run(
                    targets=targets,
                    depth=scan_config.ferox_depth,
                    threads=scan_config.threads,
                    proxy=scan_config.proxy,
                    insecure=scan_config.insecure,
                    follow_redirects=scan_config.follow_redirects,
                    extensions=extensions_for_host,
                    workdir=host_dir,
                )
                ferox_findings = _to_ferox_findings(records, in_scope_hosts)
                store.add_many(ferox_findings)
                _print_live_findings(ferox_findings, SourceTool.FEROXBUSTER, live_seen, scan_config.live_findings)
                logger.info("Feroxbuster host=%s findings=%d", host, len(ferox_findings))

    # Optional phase 7 second pass
    if scan_config.second_pass:
        _phase_header("Phase 7/8 - Second Pass Recrawl", interactive)
        second_pass_targets = [
            finding.url
            for finding in store.all()
            if SourceTool.KATANA not in finding.sources and finding.path.endswith("/")
        ]
        second_pass_targets = sorted(set(second_pass_targets))[:200]
        if second_pass_targets:
            phase7_dir = workdir / "phase7_second_pass"
            phase7_dir.mkdir(parents=True, exist_ok=True)
            second_pass_status_ctx = (
                console.status("[bold cyan]Running second-pass katana...", spinner="dots") if interactive else nullcontext()
            )
            with second_pass_status_ctx:
                records, _ = katana_runner.run(
                    targets=second_pass_targets,
                    depth=max(1, scan_config.katana_depth - 1),
                    concurrency=scan_config.katana_concurrency,
                    proxy=scan_config.proxy,
                    insecure=scan_config.insecure,
                    follow_redirects=scan_config.follow_redirects,
                    workdir=phase7_dir,
                )
            second_findings = _to_katana_findings(records, in_scope_hosts)
            store.add_many(second_findings)
            _print_live_findings(second_findings, SourceTool.KATANA, live_seen, scan_config.live_findings)
            logger.info("Second-pass katana findings=%d", len(second_findings))

    _phase_header("Phase 8/8 - Consolidation & Scoring", interactive)
    baseline_map = {}
    filtered_findings: list[Finding] = []
    for finding in store.all():
        if SourceTool.KATANA not in finding.sources and _is_noisy_status_for_bruteforce(finding.status_code):
            finding.tags.add("noise-status")
            continue

        profile = baseline_profiles.get(finding.host)
        if profile and profile.samples:
            comparison = compare_to_baseline(finding.status_code, finding.content_length, profile)
            baseline_map[finding.normalized_url] = comparison
            if (
                comparison.is_soft_404_like
                and SourceTool.KATANA not in finding.sources
                and finding.status_code not in {401, 403}
            ):
                finding.tags.add("soft-404-like")
                continue
        filtered_findings.append(finding)

    apply_scores(filtered_findings, app_config.weights, baseline_map)
    findings = sorted(filtered_findings, key=lambda item: item.score, reverse=True)

    _print_top_findings(findings)
    _write_outputs(
        findings=findings,
        output_path=scan_config.output_path,
        output_format=scan_config.output_format,
        json_shortcut=json_output,
        target_count=len(normalized_targets),
        logger=logger,
    )

    logger.info("Scan complete. Consolidated findings: %d", len(findings))


@app.command()
def check(
    config: Annotated[Path | None, typer.Option("--config", help="PathFusion TOML config")] = None,
    enable_ferox: Annotated[bool, typer.Option("--enable-ferox", help="Include feroxbuster check")] = False,
) -> None:
    """Check required external dependencies."""

    app_config = load_config(config)
    required_tools = {
        "katana": app_config.tools.katana,
        "dirsearch": app_config.tools.dirsearch,
    }
    if enable_ferox:
        required_tools["feroxbuster"] = app_config.tools.feroxbuster

    ok, statuses = _preflight(required_tools)
    _print_preflight(statuses)
    if not ok:
        for tool, (is_ok, _) in statuses.items():
            if not is_ok and tool in INSTALL_HINTS:
                console.print(INSTALL_HINTS[tool])
        raise typer.Exit(code=1)
