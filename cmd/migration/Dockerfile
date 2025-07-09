# Step 1: Build Stage.
FROM golang:1.24-alpine AS builder

ENV GO111MODULE=on
ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64

WORKDIR /app

COPY . /app

RUN go mod download

RUN go build -o main ./cmd/migration

# Step 2: Run Stage.
FROM alpine:latest

# Install tzdata to support time zones like America/Sao_Paulo.
RUN apk add --no-cache tzdata

WORKDIR /app

COPY --from=builder /app/main ./main

ENTRYPOINT [ "./main" ]
