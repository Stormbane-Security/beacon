# ── Stage 1: Build ───────────────────────────────────────────────────────────
FROM golang:1.25-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 go build -ldflags="-s -w" -o /out/beacon    ./cmd/beacon  && \
    CGO_ENABLED=1 go build -ldflags="-s -w" -o /out/beacond   ./cmd/beacond

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM debian:bookworm-slim

# System deps for SQLite (cgo) and TLS
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libsqlite3-0 \
    wget \
    unzip \
    git \
    nmap \
  && rm -rf /var/lib/apt/lists/*

# ── Install scanner tools ──────────────────────────────────────────────────────

# nuclei
RUN wget -qO /tmp/nuclei.zip \
    "https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip" && \
    unzip -q /tmp/nuclei.zip nuclei -d /usr/local/bin && \
    chmod +x /usr/local/bin/nuclei && \
    rm /tmp/nuclei.zip

# subfinder
RUN wget -qO /tmp/subfinder.zip \
    "https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_linux_amd64.zip" && \
    unzip -q /tmp/subfinder.zip subfinder -d /usr/local/bin && \
    chmod +x /usr/local/bin/subfinder && \
    rm /tmp/subfinder.zip

# gau (getallurls)
RUN wget -qO /tmp/gau.tar.gz \
    "https://github.com/lc/gau/releases/latest/download/gau_linux_amd64.tar.gz" && \
    tar -xzf /tmp/gau.tar.gz -C /usr/local/bin gau && \
    chmod +x /usr/local/bin/gau && \
    rm /tmp/gau.tar.gz

# katana (crawler)
RUN wget -qO /tmp/katana.zip \
    "https://github.com/projectdiscovery/katana/releases/latest/download/katana_linux_amd64.zip" && \
    unzip -q /tmp/katana.zip katana -d /usr/local/bin && \
    chmod +x /usr/local/bin/katana && \
    rm /tmp/katana.zip

# gowitness (screenshots) — needs chromium; skip in base image, optional via env
# GOWITNESS_BIN can be unset and gowitness scanner will be skipped gracefully.

# testssl.sh — deep TLS analysis
RUN wget -qO /tmp/testssl.sh \
    "https://raw.githubusercontent.com/drwetter/testssl.sh/3.0.9/testssl.sh" && \
    mv /tmp/testssl.sh /usr/local/bin/testssl.sh && \
    chmod +x /usr/local/bin/testssl.sh

# httpx (fast HTTP probing)
RUN wget -qO /tmp/httpx.zip \
    "https://github.com/projectdiscovery/httpx/releases/latest/download/httpx_linux_amd64.zip" && \
    unzip -q /tmp/httpx.zip httpx -d /usr/local/bin && \
    chmod +x /usr/local/bin/httpx && \
    rm /tmp/httpx.zip

# dnsx (fast DNS resolution)
RUN wget -qO /tmp/dnsx.zip \
    "https://github.com/projectdiscovery/dnsx/releases/latest/download/dnsx_linux_amd64.zip" && \
    unzip -q /tmp/dnsx.zip dnsx -d /usr/local/bin && \
    chmod +x /usr/local/bin/dnsx && \
    rm /tmp/dnsx.zip

# ffuf (fast web fuzzer)
RUN wget -qO /tmp/ffuf.tar.gz \
    "https://github.com/ffuf/ffuf/releases/latest/download/ffuf_linux_amd64.tar.gz" && \
    tar -xzf /tmp/ffuf.tar.gz -C /usr/local/bin ffuf && \
    chmod +x /usr/local/bin/ffuf && \
    rm /tmp/ffuf.tar.gz

# ── Copy binaries ─────────────────────────────────────────────────────────────
COPY --from=builder /out/beacon   /usr/local/bin/beacon
COPY --from=builder /out/beacond  /usr/local/bin/beacond

# ── Runtime config ────────────────────────────────────────────────────────────
ENV BEACON_ADDR=:8080 \
    BEACON_WORKERS=2 \
    BEACON_STORE_PATH=/data/beacon.db \
    NUCLEI_BIN=/usr/local/bin/nuclei \
    SUBFINDER_BIN=/usr/local/bin/subfinder \
    TESTSSL_BIN=/usr/local/bin/testssl.sh \
    GAU_BIN=/usr/local/bin/gau \
    KATANA_BIN=/usr/local/bin/katana \
    BEACON_HTTPX_BIN=/usr/local/bin/httpx \
    BEACON_DNSX_BIN=/usr/local/bin/dnsx \
    BEACON_FFUF_BIN=/usr/local/bin/ffuf \
    BEACON_NMAP_BIN=/usr/bin/nmap

RUN mkdir -p /data
VOLUME ["/data"]

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/beacond"]
