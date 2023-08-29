# natsmagic Dockerfile
# syntax=docker/dockerfile:1.4
FROM golang:1.20-alpine as build

WORKDIR /build

# Cache go.mod for pre-downloading dependencies and only redownloading them in subsequent builds if they change
COPY go.mod go.sum ./
RUN go mod download && go mod verify
# Copy source code
COPY . .
# Build
RUN go build -v

# Build image
FROM alpine:3 as certs

RUN apk add ca-certificates

# Final image
FROM scratch

COPY --from=certs /etc/ssl/certs /etc/ssl/certs
COPY --from=build /build/natsmagic /natsmagic

# Copy binary
# Define default command
CMD ["/natsmagic"]
