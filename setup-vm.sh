#!/usr/bin/env bash
set -euo pipefail

ARCH=$(dpkg --print-architecture)   # arm64
echo "[*] arch: $ARCH"

# ── Docker ────────────────────────────────────────────────────────────────────
echo "[*] installing docker..."
apt-get update -qq
apt-get install -y ca-certificates curl gnupg lsb-release

install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$ARCH signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" \
  > /etc/apt/sources.list.d/docker.list

apt-get update -qq
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin
systemctl enable --now docker
echo "[+] docker done"

# ── Trivy ─────────────────────────────────────────────────────────────────────
echo "[*] installing trivy..."
curl -fsSL https://aquasecurity.github.io/trivy-repo/deb/public.key \
  | gpg --dearmor -o /etc/apt/keyrings/trivy.gpg

echo \
  "deb [signed-by=/etc/apt/keyrings/trivy.gpg] \
  https://aquasecurity.github.io/trivy-repo/deb generic main" \
  > /etc/apt/sources.list.d/trivy.list

apt-get update -qq
apt-get install -y trivy
echo "[+] trivy done"

# ── Falco ─────────────────────────────────────────────────────────────────────
echo "[*] installing falco..."
curl -fsSL https://falco.org/repo/falcosecurity-packages.asc \
  | gpg --dearmor -o /etc/apt/keyrings/falco.gpg

echo \
  "deb [signed-by=/etc/apt/keyrings/falco.gpg] \
  https://download.falco.org/packages/deb stable main" \
  > /etc/apt/sources.list.d/falcosecurity.list

apt-get update -qq
# modern kernel driver — auto-selects kmod or ebpf
FALCO_FRONTEND=noninteractive apt-get install -y falco
echo "[+] falco done"

# ── networking tools ──────────────────────────────────────────────────────────
apt-get install -y iptables dnsutils net-tools

echo ""
echo "[*] done."
