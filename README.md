# container-monitor

A sandbox tool for observing the runtime network behavior and security posture of Docker container images. It runs containers in an isolated network, intercepts all DNS and HTTP(S) traffic, scans for vulnerabilities, and monitors system calls — without the containers being able to reach the real internet.

## What it does

When you run `container-monitor` with one or more image names, it:

1. **Pulls** the specified images from Docker Hub (real internet, before sandboxing).
2. **Scans** each image with [Trivy](https://github.com/aquasecurity/trivy) for known CVEs and package info.
3. **Starts [Falco](https://falco.org/)** to monitor system calls at the kernel level.
4. **Redirects DNS** (`/etc/resolv.conf`) to a local fake DNS server on `127.0.0.1`.
5. **Runs each container** inside an isolated Docker network (`sandlada`, subnet `10.10.0.0/24`) with DNS pointed at `10.10.0.1`.
6. **Intercepts DNS queries** — all lookups are logged and answered with the proxy's IP.
7. **Intercepts HTTP/HTTPS traffic** via an HTTP proxy on port 8080 — all outbound connections are logged.
8. **Logs everything** to `monitor.log` (DNS + proxy) and `trivy.log` (CVE scan results).
9. **Cleans up** containers and restores real DNS on exit (SIGINT/SIGTERM).

This lets you answer: *What domains does this image try to reach? What does it download? Does it have known vulnerabilities?*

## Prerequisites

The following tools must be installed on the host machine:

| Tool | Purpose |
|------|---------|
| [Docker](https://docs.docker.com/engine/install/) | Running and managing containers |
| [Falco](https://falco.org/docs/getting-started/installation/) | Kernel-level syscall monitoring |
| [Trivy](https://aquasecurity.github.io/trivy/latest/getting-started/installation/) | Container image vulnerability scanning |
| Go 1.21+ | Building the monitor binary |

## Setting up a VM (Ubuntu 22.04 / 24.04)

### 1. Install Docker

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker
```

### 2. Install Falco

```bash
curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | sudo gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" | sudo tee /etc/apt/sources.list.d/falcosecurity.list
sudo apt-get update
sudo apt-get install -y falco
```

### 3. Install Trivy

```bash
sudo apt-get install -y wget apt-transport-https gnupg
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo gpg --dearmor -o /usr/share/keyrings/trivy.gpg
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" | sudo tee /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install -y trivy
```

### 4. Create the sandbox Docker network

```bash
docker network create \
  --driver bridge \
  --subnet 10.10.0.0/24 \
  --gateway 10.10.0.1 \
  sandlada
```

### 5. Build the monitor binary

```bash
git clone https://github.com/gustavhammarin/container-monitor.git
cd container-monitor
go build -o monitor ./cmd/monitor
```

### 6. Run

The binary must run as root (it binds to port 53 and modifies `/etc/resolv.conf`).

```bash
sudo ./monitor alpine:latest nginx:latest
```

Logs are written to the directory containing the binary:
- `monitor.log` — DNS queries and proxy traffic (JSON, one entry per line)
- `trivy.log` — Trivy vulnerability scan results (JSON)
- `falco.log` — Falco security alerts (JSON)

Press `Ctrl+C` to stop. Containers are removed and DNS is restored automatically.

## Output format

### monitor.log — DNS entry
```json
{"timestamp":"2026-04-23T16:04:18Z","source":"127.0.0.1:56761","domain":"example.com","query_type":"A","type":"DNS"}
```

### monitor.log — Proxy entry
```json
{"timestamp":"2026-04-23T16:04:20Z","source":"10.10.0.2:43210","domain":"example.com","method":"GET","path":"/index.html","type":"PROXY_HTTP"}
```

## Notes

- The sandbox network name `sandlada` is Swedish for "sandbox".
- Containers are named after their image (`:` and `/` replaced with `-`), e.g. `alpine-latest`.
- HTTPS tunneling is intercepted at the `CONNECT` level — the domain is logged but the payload is not decrypted.
- `/etc/resolv.conf` is temporarily overwritten during the run. If the process crashes, restore it manually: `echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf`
