FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY main.go .
RUN go build -o server main.go

FROM alpine:3.21
COPY --from=builder /app/server /server
ENTRYPOINT ["/server"]
