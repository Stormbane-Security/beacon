FROM golang:1.22-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /beacon ./cmd/beacon

# Install external scan tools
FROM alpine:3.19 AS tools

RUN apk add --no-cache curl bash go

# nuclei + subfinder via go install
ENV PATH="/root/go/bin:$PATH"
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# testssl.sh
RUN curl -fsSL https://github.com/drwetter/testssl.sh/archive/refs/tags/v3.2.tar.gz \
    | tar xz -C /tmp && \
    mv /tmp/testssl.sh-3.2/testssl.sh /usr/local/bin/testssl.sh && \
    chmod +x /usr/local/bin/testssl.sh && \
    rm -rf /tmp/testssl.sh-3.2

# Final image
FROM alpine:3.19

RUN apk add --no-cache ca-certificates bash openssl

COPY --from=builder /beacon /usr/local/bin/beacon
COPY --from=tools /root/go/bin/nuclei /usr/local/bin/nuclei
COPY --from=tools /root/go/bin/subfinder /usr/local/bin/subfinder
COPY --from=tools /usr/local/bin/testssl.sh /usr/local/bin/testssl.sh

RUN mkdir -p /root/.beacon

ENTRYPOINT ["beacon"]
CMD ["--help"]
