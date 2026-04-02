FROM golang:1.23-alpine AS build
WORKDIR /app
COPY main.go .
RUN go build -o spring-app main.go

FROM alpine:3.19
COPY --from=build /app/spring-app /usr/local/bin/spring-app
EXPOSE 8080
CMD ["spring-app"]
