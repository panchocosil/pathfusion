# PathFusion

PathFusion is a production-oriented Python CLI for **authorized** web content discovery.

It combines:

- `katana` for crawling and URL discovery
- `dirsearch` for directory/file brute forcing
- `feroxbuster` for recursive forced browsing on high-value paths

PathFusion is not a simple tool chain wrapper. It adds an **intelligence layer** that correlates discovered evidence and decides what to scan next.

## Security and Authorization Notice

Use PathFusion only on targets you own or where you have explicit written authorization.

PathFusion intentionally avoids:

- exploit payload execution
- credential attacks
- bypass logic
- destructive actions

It focuses on reconnaissance and content discovery.

## Key Features

- Multi-phase scan pipeline with source attribution (`katana`, `dirsearch`, `feroxbuster`)
- Host-scoped normalization and deduplication
- Path intelligence:
  - parent directory extraction
  - sensitive keyword tagging
  - observed extension extraction
- Soft-404/wildcard baseline reduction
- Score-based prioritization with tunable weights
- Optional second-pass recrawl loop
- Interactive terminal UX (phase banners + progress bars)
- Multiple outputs: terminal, JSON, JSONL, CSV, Markdown

## Architecture

- `pathfusion/cli.py`: main orchestration and CLI
- `pathfusion/runners/`: subprocess wrappers for external tools
- `pathfusion/analyzers/`: normalization, correlation, baseline, scoring
- `pathfusion/storage/store.py`: dedup and merge store
- `pathfusion/reports/`: exporters
- `pathfusion/tests/`: unit tests for core logic

## Project Layout

```text
pathfusion/
  __init__.py
  cli.py
  config.py
  models.py
  utils.py
  analyzers/
    __init__.py
    baseline.py
    correlate.py
    normalize.py
    paths.py
    scoring.py
  reports/
    __init__.py
    csv_report.py
    json_report.py
    markdown_report.py
  runners/
    __init__.py
    dirsearch.py
    feroxbuster.py
    katana.py
  storage/
    __init__.py
    store.py
  tests/
    test_baseline.py
    test_normalize.py
    test_paths.py
    test_scoring.py
    test_store.py
pyproject.toml
pathfusion.example.toml
README.md
```

## Requirements

- Python 3.11+
- Tools in `PATH`:
  - `katana`
  - `dirsearch`
  - `feroxbuster` (required only when `--enable-ferox`)

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

If your system Python is externally managed, always use a virtual environment.

## Dependency Check

```bash
pathfusion check
pathfusion check --enable-ferox
pathfusion scan --check
```

## Quick Start

Single target:

```bash
pathfusion scan -u https://target.tld
```

Target list:

```bash
pathfusion scan -l targets.txt
```

Interactive + verbose run:

```bash
pathfusion scan -l targets.txt --interactive --verbose
```

## Accepted Target Formats

PathFusion accepts all of these in `-u` or `-l`:

- `example.com` (normalized to `https://example.com/`)
- `https://example.com`
- `https://example.com:443`
- `http://example.com:8080`

One target per line in list files.

## Pipeline (What Happens Internally)

1. **Input normalization**
   - normalize URLs
   - deduplicate
   - group by host
2. **Katana discovery**
   - crawl and collect URL evidence
3. **Correlation engine**
   - derive parent paths
   - detect extensions
   - tag sensitive patterns
4. **Baseline profiling**
   - probe random non-existing paths per host
   - estimate soft-404 behavior
5. **Dirsearch expansion**
   - run on root plus high-value parent paths from previous evidence
6. **Feroxbuster recursion (optional)**
   - only for high-value/scored paths when `--enable-ferox`
7. **Second-pass recrawl (optional)**
   - recrawl newly discovered directory-like paths
8. **Consolidation and scoring**
   - merge duplicates
   - apply weighted scoring
   - export reports

## Redirect Behavior

Global redirect policy is explicit:

- Default: `--no-follow-redirects`
- Optional: `--follow-redirects`

This policy is propagated through baseline probing and supported external-tool flags when available.

## Wordlist Behavior

Dirsearch wordlist priority:

1. `--wordlist` CLI value
2. first entry in `default_wordlists` from `--config`
3. dirsearch default wordlist (if neither provided)

## When Feroxbuster Runs

Feroxbuster runs only if:

1. `--enable-ferox` is set
2. PathFusion identified high-value targets from prior evidence (score/tags)

If no high-value paths are found, the ferox phase is skipped.

## False Positive Reduction

PathFusion applies multiple controls:

- baseline soft-404 comparison (status + content-length similarity)
- wildcard/soft-404 filtering for brute-force-only findings
- noisy status filtering for brute-force-only results (`404`, `410`, selected `5xx`, etc.)
- aggressive deduplication and source merging

## Interactive Scanner UX

By default (`--interactive`), PathFusion shows:

- phase headers (`Phase 1/8 ... 8/8`)
- live progress bars for baseline, dirsearch, and ferox phases
- status spinners for katana and second-pass recrawl

Use `--no-interactive` for CI/log-friendly output.

## CLI Options

- `-u, --url`: target URL (repeatable)
- `-l, --list`: file with target URLs
- `--proxy`: HTTP(S) proxy URL
- `--insecure/--secure`: disable/enable TLS certificate verification (default: insecure)
- `--follow-redirects/--no-follow-redirects`: redirect handling (default: no-follow)
- `--katana-depth`: katana crawl depth
- `--katana-concurrency`: katana concurrency
- `--wordlist`: dirsearch wordlist file
- `--extensions`: comma-separated extensions
- `--enable-ferox`: enable ferox phase
- `--ferox-depth`: ferox recursion depth
- `--threads`: brute-force threads
- `--dirsearch-timeout`: dirsearch request timeout in seconds (default: `10`)
- `-H, --header`: custom header for dirsearch (repeatable)
- `--dirsearch-full-url/--no-dirsearch-full-url`: toggle `--full-url` (default: on)
- `--dirsearch-random-agent/--no-dirsearch-random-agent`: toggle random user-agent (default: on)
- `--baseline-samples`: baseline probes per host (default: `3`)
- `--baseline-timeout`: baseline probe timeout in seconds (default: `10`)
- `--skip-baseline`: skip baseline profiling phase
- `--output`: output report path
- `--output-format`: `pretty|json|jsonl|csv|markdown`
- `--json`: JSON shortcut output path
- `--second-pass`: enable recrawl loop
- `--max-hosts`: limit distinct hosts
- `--check`: dependency check and exit
- `--verbose`: debug-level logs (includes executed commands)
- `--interactive/--no-interactive`: interactive UI toggle
- `--config`: TOML config path

## Output Formats

- terminal summary table
- JSON (`--json` or `--output-format json`)
- JSONL
- CSV
- Markdown summary report

Each finding can include:

- `url`, `normalized_url`, `host`, `path`, `parent_path`
- source attribution
- status and content length (if available)
- tags
- score and scoring reasons

## Config File

Use `pathfusion.example.toml` as a base:

```bash
pathfusion scan -l targets.txt --config pathfusion.example.toml
```

Supports defaults for:

- tool binary paths
- proxy and TLS behavior
- default wordlists/extensions
- scoring weights
- host allow/deny patterns
- recursion policy limits

## Examples

Basic scan:

```bash
pathfusion scan -u https://target.tld
```

List scan with custom extensions:

```bash
pathfusion scan -l targets.txt --extensions php,txt,json,bak
```

Dirsearch-style tuning (timeout + headers + full-url + random-agent):

```bash
pathfusion scan -u https://target.tld \
  --dirsearch-timeout 10 \
  -H \"X-Originating-IP: 127.0.0.1\" \
  -H \"X-Forwarded-For: 127.0.0.1\" \
  -H \"X-Remote-IP: 127.0.0.1\" \
  -H \"X-Remote-Addr: 127.0.0.1\" \
  --dirsearch-full-url \
  --dirsearch-random-agent
```

Full recursive flow:

```bash
pathfusion scan -l targets.txt \
  --enable-ferox \
  --second-pass \
  --follow-redirects \
  --interactive \
  --verbose \
  --output report.md \
  --output-format markdown \
  --json findings.json
```

Large list / faster mode:

```bash
pathfusion scan -l targets.txt \
  --interactive \
  --baseline-samples 1 \
  --baseline-timeout 3
```

## Troubleshooting

If `pathfusion` command is not found:

```bash
source .venv/bin/activate
which pathfusion
```

If dependencies appear installed but scan fails:

```bash
pathfusion check --enable-ferox
pathfusion scan -u https://target.tld --verbose
```

Look for runner command lines and tool stderr in verbose logs.

If results are noisy:

- keep `--no-follow-redirects` (default)
- provide a tighter wordlist
- reduce extension list with `--extensions`
- keep `--verbose` and inspect tool-level behavior

If scans are too slow on very large target lists:

- reduce baseline cost with `--baseline-samples 1 --baseline-timeout 3`
- or skip baseline entirely with `--skip-baseline`

## Testing

```bash
python -m pytest
```

Covered unit tests include:

- URL normalization
- parent path extraction
- scoring behavior
- finding dedup/merge
- baseline comparison logic

## Current Limitations

- External tool output formats differ by version; parsers are defensive but generic.
- Scope model is host-centric (not full org asset graph yet).
- Baseline logic is intentionally lightweight for speed.
- Execution is sequential per phase (not fully async yet).

## Roadmap / TODO

- async orchestration for higher throughput
- richer scope controls (CIDR/wildcards/path constraints)
- adaptive recursion budgets by confidence
- optional HTTP revalidation of top findings
- plugin hooks for custom analyzers
- integration test fixtures for tool output variants
- HTML/SARIF reporting
