FROM golang:1.23-alpine AS build
WORKDIR /app
COPY main.go .
RUN go build -o server main.go

FROM alpine:3.19
RUN apk add --no-cache iputils curl netcat-openbsd
COPY --from=build /app/server /server
EXPOSE 8080
CMD ["/server"]
