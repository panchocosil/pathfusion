#!/usr/bin/env bash
set -euo pipefail

KATANA_REPO="projectdiscovery/katana"
DIRSEARCH_REPO_URL="https://github.com/maurosoria/dirsearch.git"
FEROX_REPO="epi052/feroxbuster"

DIRSEARCH_INSTALL_BASE="${HOME}/.local/share"
DIRSEARCH_INSTALL_DIR="${DIRSEARCH_INSTALL_BASE}/dirsearch"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[-] Falta dependencia: $1"
    exit 1
  }
}

log() {
  echo "[*] $*"
}

ok() {
  echo "[+] $*"
}

warn() {
  echo "[!] $*"
}

detect_os_arch() {
  OS_RAW="$(uname -s)"
  ARCH_RAW="$(uname -m)"

  case "$OS_RAW" in
    Linux) OS="linux" ;;
    Darwin) OS="macOS" ;;
    *)
      echo "[-] Sistema no soportado: $OS_RAW"
      exit 1
      ;;
  esac

  case "$ARCH_RAW" in
    x86_64|amd64) ARCH="amd64" ;;
    arm64|aarch64) ARCH="arm64" ;;
    i386|i686) ARCH="386" ;;
    *)
      echo "[-] Arquitectura no soportada: $ARCH_RAW"
      exit 1
      ;;
  esac

  log "Detectado OS=$OS ARCH=$ARCH"
}

setup_hash_cmd() {
  if command -v sha256sum >/dev/null 2>&1; then
    SHA_CMD="sha256sum"
  elif command -v shasum >/dev/null 2>&1; then
    SHA_CMD="shasum -a 256"
  else
    echo "[-] No encontré sha256sum ni shasum"
    exit 1
  fi
}

choose_install_bin_dir() {
  if [[ -w "/usr/local/bin" ]]; then
    INSTALL_BIN_DIR="/usr/local/bin"
  else
    INSTALL_BIN_DIR="${HOME}/.local/bin"
    mkdir -p "$INSTALL_BIN_DIR"
  fi
  ok "Binarios/comandos se instalarán en: $INSTALL_BIN_DIR"
}

detect_shell_rc() {
  if [[ -n "${ZSH_VERSION:-}" ]]; then
    SHELL_RC="$HOME/.zshrc"
  elif [[ -n "${BASH_VERSION:-}" ]]; then
    SHELL_RC="$HOME/.bashrc"
  elif [[ -n "${SHELL:-}" && "$SHELL" == *"zsh" ]]; then
    SHELL_RC="$HOME/.zshrc"
  else
    SHELL_RC="$HOME/.bashrc"
  fi
}

ensure_bin_dir_in_path() {
  local target_dir="$1"
  detect_shell_rc

  if [[ ":$PATH:" == *":${target_dir}:"* ]]; then
    ok "${target_dir} ya está en PATH para esta sesión"
    return 0
  fi

  local export_line="export PATH=\"${target_dir}:\$PATH\""

  if [[ ! -f "$SHELL_RC" ]] || ! grep -Fq "$export_line" "$SHELL_RC"; then
    log "Agregando ${target_dir} al PATH en ${SHELL_RC}"
    {
      echo ""
      echo "# Added by katana+dirsearch+feroxbuster installer"
      echo "$export_line"
    } >> "$SHELL_RC"
  else
    log "${target_dir} ya estaba configurado en ${SHELL_RC}"
  fi

  export PATH="${target_dir}:$PATH"
  ok "PATH actualizado para esta sesión"
  warn "Para futuras sesiones, abre una nueva terminal o ejecuta: source ${SHELL_RC}"
}

github_latest_release_json() {
  local repo="$1"
  curl -fsSL "https://api.github.com/repos/${repo}/releases/latest"
}

install_katana() {
  need_cmd curl
  need_cmd unzip
  need_cmd grep
  need_cmd sed
  need_cmd awk
  need_cmd find

  log "Consultando latest release de Katana..."
  local json version version_clean zip_name checksum_name base_url zip_url checksum_url
  json="$(github_latest_release_json "$KATANA_REPO")"
  version="$(printf '%s' "$json" | grep -m1 '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')"

  if [[ -z "$version" ]]; then
    echo "[-] No pude obtener la última versión de Katana desde GitHub API"
    exit 1
  fi

  version_clean="${version#v}"
  zip_name="katana_${version_clean}_${OS}_${ARCH}.zip"

  if [[ "$OS" == "linux" ]]; then
    checksum_name="katana-linux-checksums.txt"
  else
    checksum_name="katana-mac-checksums.txt"
  fi

  base_url="https://github.com/${KATANA_REPO}/releases/download/${version}"
  zip_url="${base_url}/${zip_name}"
  checksum_url="${base_url}/${checksum_name}"

  local tmp_dir
  tmp_dir="$(mktemp -d)"

  log "Descargando Katana: ${zip_name}"
  curl -fL "$zip_url" -o "${tmp_dir}/${zip_name}"

  log "Descargando checksums: ${checksum_name}"
  curl -fL "$checksum_url" -o "${tmp_dir}/${checksum_name}"

  log "Verificando SHA256 de Katana..."
  local expected_hash actual_hash
  expected_hash="$(grep " ${zip_name}\$" "${tmp_dir}/${checksum_name}" | awk '{print $1}')"

  if [[ -z "$expected_hash" ]]; then
    echo "[-] No encontré hash para ${zip_name} en ${checksum_name}"
    rm -rf "$tmp_dir"
    exit 1
  fi

  actual_hash="$($SHA_CMD "${tmp_dir}/${zip_name}" | awk '{print $1}')"

  if [[ "$expected_hash" != "$actual_hash" ]]; then
    echo "[-] SHA256 de Katana no coincide"
    echo "    Esperado: $expected_hash"
    echo "    Actual:   $actual_hash"
    rm -rf "$tmp_dir"
    exit 1
  fi

  ok "Checksum de Katana OK"

  log "Extrayendo Katana..."
  unzip -qo "${tmp_dir}/${zip_name}" -d "${tmp_dir}/extract"

  local katana_bin
  katana_bin="$(find "${tmp_dir}/extract" -type f -name katana | head -n 1)"
  if [[ -z "$katana_bin" ]]; then
    echo "[-] No encontré el binario katana dentro del zip"
    rm -rf "$tmp_dir"
    exit 1
  fi

  chmod +x "$katana_bin"
  cp "$katana_bin" "${INSTALL_BIN_DIR}/katana"
  chmod +x "${INSTALL_BIN_DIR}/katana"

  rm -rf "$tmp_dir"
  ok "Katana instalado en ${INSTALL_BIN_DIR}/katana"
}

install_dirsearch() {
  need_cmd git
  need_cmd python3

  log "Verificando versión de Python para dirsearch..."
  python3 - <<'PY'
import sys
if sys.version_info < (3, 9):
    raise SystemExit("[-] dirsearch requiere Python 3.9+")
print("[+] Python compatible para dirsearch:", sys.version.split()[0])
PY

  mkdir -p "$DIRSEARCH_INSTALL_BASE"

  if [[ -d "$DIRSEARCH_INSTALL_DIR/.git" ]]; then
    log "dirsearch ya existe, actualizando repo..."
    git -C "$DIRSEARCH_INSTALL_DIR" fetch --depth 1 origin
    git -C "$DIRSEARCH_INSTALL_DIR" reset --hard origin/master
  else
    log "Clonando dirsearch..."
    rm -rf "$DIRSEARCH_INSTALL_DIR"
    git clone --depth 1 "$DIRSEARCH_REPO_URL" "$DIRSEARCH_INSTALL_DIR"
  fi

  if [[ ! -f "${DIRSEARCH_INSTALL_DIR}/dirsearch.py" ]]; then
    echo "[-] No encontré dirsearch.py en ${DIRSEARCH_INSTALL_DIR}"
    exit 1
  fi

  cat > "${INSTALL_BIN_DIR}/dirsearch" <<EOF
#!/usr/bin/env bash
exec python3 "${DIRSEARCH_INSTALL_DIR}/dirsearch.py" "\$@"
EOF

  chmod +x "${INSTALL_BIN_DIR}/dirsearch"

  ok "dirsearch instalado en ${DIRSEARCH_INSTALL_DIR}"
  ok "Wrapper creado en ${INSTALL_BIN_DIR}/dirsearch"
}

pick_ferox_asset_pattern() {
  case "${OS}:${ARCH}" in
    linux:amd64)   echo "x86_64-linux" ;;
    linux:arm64)   echo "aarch64-linux" ;;
    macOS:amd64)   echo "x86_64-macos" ;;
    macOS:arm64)   echo "aarch64-macos" ;;
    *)
      return 1
      ;;
  esac
}

install_feroxbuster() {
  need_cmd curl
  need_cmd tar
  need_cmd grep
  need_cmd sed

  local asset_pattern
  asset_pattern="$(pick_ferox_asset_pattern)" || {
    echo "[-] No hay patrón de asset configurado para ${OS}/${ARCH} en feroxbuster"
    exit 1
  }

  log "Consultando latest release de feroxbuster..."
  local json version asset_url asset_name tmp_dir ferox_bin
  json="$(github_latest_release_json "$FEROX_REPO")"
  version="$(printf '%s' "$json" | grep -m1 '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')"

  if [[ -z "$version" ]]; then
    echo "[-] No pude obtener la última versión de feroxbuster desde GitHub API"
    exit 1
  fi

  asset_url="$(
    printf '%s' "$json" \
      | grep '"browser_download_url":' \
      | sed -E 's/.*"([^"]+)".*/\1/' \
      | grep "${asset_pattern}" \
      | grep -E '\.(tar\.gz|tgz)$' \
      | head -n 1
  )"

  if [[ -z "$asset_url" ]]; then
    echo "[-] No pude encontrar un asset de feroxbuster para ${OS}/${ARCH}"
    echo "[-] Patrón buscado: ${asset_pattern}"
    exit 1
  fi

  asset_name="$(basename "$asset_url")"
  tmp_dir="$(mktemp -d)"

  log "Latest feroxbuster: ${version}"
  log "Descargando feroxbuster: ${asset_name}"
  curl -fL "$asset_url" -o "${tmp_dir}/${asset_name}"

  log "Extrayendo feroxbuster..."
  tar -xzf "${tmp_dir}/${asset_name}" -C "${tmp_dir}"

  ferox_bin="$(find "${tmp_dir}" -type f -name feroxbuster | head -n 1)"
  if [[ -z "$ferox_bin" ]]; then
    echo "[-] No encontré el binario feroxbuster en el tarball"
    rm -rf "$tmp_dir"
    exit 1
  fi

  chmod +x "$ferox_bin"
  cp "$ferox_bin" "${INSTALL_BIN_DIR}/feroxbuster"
  chmod +x "${INSTALL_BIN_DIR}/feroxbuster"

  rm -rf "$tmp_dir"
  ok "feroxbuster instalado en ${INSTALL_BIN_DIR}/feroxbuster"
}

verify_install() {
  echo
  log "Verificando instalación final..."

  if command -v katana >/dev/null 2>&1; then
    echo "katana => $(command -v katana)"
    katana -version || katana --version || true
  else
    warn "katana no quedó visible en PATH todavía"
  fi

  echo

  if command -v dirsearch >/dev/null 2>&1; then
    echo "dirsearch => $(command -v dirsearch)"
    dirsearch --help >/dev/null 2>&1 && ok "dirsearch responde correctamente"
  else
    warn "dirsearch no quedó visible en PATH todavía"
  fi

  echo

  if command -v feroxbuster >/dev/null 2>&1; then
    echo "feroxbuster => $(command -v feroxbuster)"
    feroxbuster --version || true
  else
    warn "feroxbuster no quedó visible en PATH todavía"
  fi
}

main() {
  detect_os_arch
  setup_hash_cmd
  choose_install_bin_dir

  install_katana
  install_dirsearch
  install_feroxbuster

  ensure_bin_dir_in_path "$INSTALL_BIN_DIR"
  verify_install

  echo
  ok "Listo. Comandos disponibles:"
  echo "    katana"
  echo "    dirsearch"
  echo "    feroxbuster"
}

main "$@"
