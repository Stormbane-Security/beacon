FROM golang:1.23-alpine AS build
WORKDIR /app
COPY main.go .
RUN go build -o csrf-app main.go

FROM alpine:3.19
COPY --from=build /app/csrf-app /usr/local/bin/csrf-app
EXPOSE 8080
CMD ["csrf-app"]
