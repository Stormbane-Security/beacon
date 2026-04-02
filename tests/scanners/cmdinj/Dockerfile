FROM golang:1.23-alpine AS build
RUN apk add --no-cache iputils bind-tools
WORKDIR /app
COPY main.go .
RUN go build -o cmdinj-app main.go

FROM alpine:3.19
RUN apk add --no-cache iputils bind-tools
COPY --from=build /app/cmdinj-app /usr/local/bin/cmdinj-app
EXPOSE 8080
CMD ["cmdinj-app"]
