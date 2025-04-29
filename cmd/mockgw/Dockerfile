# Step 1: Build Stage.
FROM golang:1.24-alpine AS builder

ENV GO111MODULE=on
ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64

WORKDIR /

COPY . .

RUN go mod download

RUN go build -o main

# Step 2: Run Stage.
FROM alpine:latest

WORKDIR /

COPY --from=builder /main ./main

EXPOSE 443

ENTRYPOINT [ "./main" ]
