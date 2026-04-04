FROM golang:1.25-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /beacon ./cmd/beacon

# Install external scan tools
FROM golang:1.25-alpine AS tools

RUN apk add --no-cache curl bash git nmap nmap-scripts build-base

ENV PATH="/root/go/bin:$PATH"
ENV GOBIN="/root/go/bin"

# projectdiscovery tools
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN CGO_ENABLED=1 go install github.com/projectdiscovery/katana/cmd/katana@latest

# OSINT / recon tools
RUN go install github.com/owasp-amass/amass/v4/...@master
RUN go install github.com/lc/gau/v2/cmd/gau@latest

# testssl.sh — download the script directly from the 3.2 branch
RUN curl -fsSL https://raw.githubusercontent.com/drwetter/testssl.sh/3.2/testssl.sh \
    -o /usr/local/bin/testssl.sh && \
    chmod +x /usr/local/bin/testssl.sh

# Final image
FROM alpine:3.21

RUN apk add --no-cache ca-certificates bash openssl nmap nmap-scripts curl bind-tools

COPY --from=builder /beacon /usr/local/bin/beacon
COPY --from=tools /root/go/bin/nuclei /usr/local/bin/nuclei
COPY --from=tools /root/go/bin/subfinder /usr/local/bin/subfinder
COPY --from=tools /root/go/bin/katana /usr/local/bin/katana
COPY --from=tools /root/go/bin/amass /usr/local/bin/amass
COPY --from=tools /root/go/bin/gau /usr/local/bin/gau
COPY --from=tools /usr/local/bin/testssl.sh /usr/local/bin/testssl.sh

RUN adduser -D -s /bin/false -h /home/beacon beacon && \
    mkdir -p /home/beacon/.beacon && \
    chown -R beacon:beacon /home/beacon

USER beacon
ENTRYPOINT ["beacon"]
CMD ["--help"]
