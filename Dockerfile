# Step 1: Build Stage.
FROM golang:1.24-alpine AS builder

ENV GO111MODULE=on
ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64

WORKDIR /app

COPY . .

RUN go mod download

RUN go build -o main ./cmd/lambda

# Step 2: Run Stage.
FROM alpine:latest

WORKDIR /app

COPY --from=builder /app/main ./

EXPOSE 80

CMD ["./main"]