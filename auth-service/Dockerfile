FROM golang:1.22-alpine as builder
RUN apk add --no-cache dpkg gcc git musl-dev openssh

WORKDIR /app
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -a -v -installsuffix cgo -o app ./


FROM alpine:latest

COPY --from=builder /app/app ./

EXPOSE 8080

CMD ["./app"]