FROM golang:1.22-alpine AS build
WORKDIR /app
COPY main.go .
RUN go mod init wstest && go mod tidy && go build -o server main.go

FROM alpine:3.19
COPY --from=build /app/server /server
EXPOSE 8080
CMD ["/server"]
