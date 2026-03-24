#!/usr/bin/env bash
# Install external tools required by Beacon scanners.
# All tools are open-source with permissive licenses (MIT or Apache 2.0),
# except testssl.sh (GPLv2 — used as a subprocess only, not embedded).
set -euo pipefail

info()  { echo "[+] $*"; }
warn()  { echo "[!] $*" >&2; }
check() { command -v "$1" &>/dev/null; }

# Ensure Go bin directory is on PATH
export PATH="$PATH:$(go env GOPATH)/bin"

# --- nuclei (MIT) — primary scanner ---
if check nuclei; then
  info "nuclei already installed: $(nuclei -version 2>&1 | head -1)"
else
  info "installing nuclei..."
  go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
fi

# --- subfinder (MIT) — passive subdomain enumeration ---
if check subfinder; then
  info "subfinder already installed"
else
  info "installing subfinder..."
  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
fi

# --- amass (Apache 2.0) — OSINT asset discovery ---
if check amass; then
  info "amass already installed"
else
  info "installing amass..."
  go install -v github.com/owasp-amass/amass/v4/...@master
fi

# --- gau (MIT) — historical URLs from Wayback Machine + OTX ---
if check gau; then
  info "gau already installed"
else
  info "installing gau..."
  go install -v github.com/lc/gau/v2/cmd/gau@latest
fi

# --- katana (MIT) — JS-aware web crawler ---
if check katana; then
  info "katana already installed"
else
  info "installing katana..."
  go install -v github.com/projectdiscovery/katana/cmd/katana@latest
fi

# --- gowitness (Apache 2.0) — screenshot capture (requires Chrome/Chromium) ---
if check gowitness; then
  info "gowitness already installed"
else
  info "installing gowitness..."
  go install -v github.com/sensepost/gowitness@latest
fi

# Warn if no browser found for gowitness
HAS_BROWSER=false
for b in chromium chromium-browser google-chrome google-chrome-stable; do
  if check "$b"; then HAS_BROWSER=true; break; fi
done
if [ -f "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" ] || \
   [ -f "/Applications/Chromium.app/Contents/MacOS/Chromium" ]; then
  HAS_BROWSER=true
fi
if [ "$HAS_BROWSER" = false ]; then
  warn "gowitness requires Chrome or Chromium — screenshots will be skipped."
  warn "Install Chrome: https://www.google.com/chrome/"
fi

# --- testssl.sh (GPLv2 — subprocess only, not embedded) ---
TESTSSL_BIN="/usr/local/bin/testssl.sh"
if check testssl.sh; then
  info "testssl.sh already installed"
elif [ -f "$TESTSSL_BIN" ]; then
  info "testssl.sh found at $TESTSSL_BIN"
else
  info "installing testssl.sh..."
  TESTSSL_VERSION="3.2"
  TMP=$(mktemp -d)
  curl -fsSL "https://github.com/drwetter/testssl.sh/archive/refs/tags/v${TESTSSL_VERSION}.tar.gz" \
    | tar xz -C "$TMP"
  chmod +x "$TMP/testssl.sh-${TESTSSL_VERSION}/testssl.sh"
  sudo mv "$TMP/testssl.sh-${TESTSSL_VERSION}/testssl.sh" "$TESTSSL_BIN"
  rm -rf "$TMP"
  info "testssl.sh installed to $TESTSSL_BIN"
fi

# --- httpx (MIT) — fast HTTP probing ---
if check httpx; then
  info "httpx already installed"
else
  info "installing httpx..."
  go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
fi

# --- dnsx (MIT) — fast DNS resolution ---
if check dnsx; then
  info "dnsx already installed"
else
  info "installing dnsx..."
  go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
fi

# --- ffuf (MIT) — fast web fuzzer for dirbust ---
if check ffuf; then
  info "ffuf already installed"
else
  info "installing ffuf..."
  go install -v github.com/ffuf/ffuf/v2@latest
fi

info "all tools installed"
echo ""
echo "Tools summary:"
echo "  nuclei:     $(which nuclei 2>/dev/null || echo 'not found')"
echo "  subfinder:  $(which subfinder 2>/dev/null || echo 'not found')"
echo "  amass:      $(which amass 2>/dev/null || echo 'not found')"
echo "  gau:        $(which gau 2>/dev/null || echo 'not found')"
echo "  katana:     $(which katana 2>/dev/null || echo 'not found')"
echo "  gowitness:  $(which gowitness 2>/dev/null || echo 'not found')"
echo "  testssl.sh: $(which testssl.sh 2>/dev/null || echo 'not found')"
echo "  httpx:      $(which httpx 2>/dev/null || echo 'not found')"
echo "  dnsx:       $(which dnsx 2>/dev/null || echo 'not found')"
echo "  ffuf:       $(which ffuf 2>/dev/null || echo 'not found')"
