#!/usr/bin/env bash
# Shows exactly what would be installed. Does nothing unless you pass --yes.
# Designed for Kali Linux (Go toolchain + apt). Run as the user who will
# run recon.sh - ProjectDiscovery tools install under $GOPATH/bin / ~/go/bin.
set -Eeuo pipefail

APPLY=0
[[ "${1:-}" == "--yes" ]] && APPLY=1

APT_PKGS=(curl dnsutils golang-go python3 python3-pip python3-yaml git)
GO_TOOLS=(
  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  "github.com/projectdiscovery/httpx/cmd/httpx@latest"
  "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  "github.com/projectdiscovery/katana/cmd/katana@latest"
  "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  "github.com/lc/gau/v2/cmd/gau@latest"
  "github.com/tomnomnom/waybackurls@latest"
  "github.com/ffuf/ffuf/v2@latest"
)
# amass is packaged separately (apt install amass, or OWASP's own releases)

echo "== reconkit dependency plan =="
echo
echo "apt packages:"
printf '  %s\n' "${APT_PKGS[@]}" "amass"
echo
echo "go install (to \$(go env GOPATH)/bin, make sure that's on PATH):"
printf '  %s\n' "${GO_TOOLS[@]}"
echo
echo "nuclei templates (nuclei -update-templates) will also be fetched."
echo

if (( ! APPLY )); then
  echo "Dry run only - nothing was installed. Re-run with --yes to actually install."
  echo "(No step here runs silently or without this explicit flag.)"
  exit 0
fi

read -r -p "This will run apt-get install and go install for the tools above. Continue? [y/N] " confirm
[[ "$confirm" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 1; }

sudo apt-get update
sudo apt-get install -y "${APT_PKGS[@]}" amass
pip install --break-system-packages pyyaml || pip install pyyaml

for tool in "${GO_TOOLS[@]}"; do
  echo "Installing: $tool"
  go install -v "$tool"
done

echo
echo "Done. Ensure \$(go env GOPATH)/bin is on your PATH, then run: ./recon.sh --check"
echo "Optionally run: nuclei -update-templates"
