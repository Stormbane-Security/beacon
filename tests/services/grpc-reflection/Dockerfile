FROM golang:1.22-alpine AS build
WORKDIR /app
RUN go mod init grpc-server && \
    go get google.golang.org/grpc && \
    go get google.golang.org/grpc/reflection && \
    go get google.golang.org/grpc/health && \
    go get google.golang.org/grpc/health/grpc_health_v1
COPY main.go .
RUN go build -o server main.go

FROM alpine:3.19
COPY --from=build /app/server /server
EXPOSE 50051
CMD ["/server"]
