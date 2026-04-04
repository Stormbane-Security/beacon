FROM golang:1.22-alpine AS build
WORKDIR /src
COPY main.go .
RUN go build -o /app/server main.go

FROM alpine:3.19
COPY --from=build /app/server /app/server
RUN mkdir -p /app/public && echo "Hello from the file viewer" > /app/public/readme.txt
EXPOSE 8080
CMD ["/app/server"]
