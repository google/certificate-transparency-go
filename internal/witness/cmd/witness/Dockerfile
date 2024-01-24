FROM golang:1.21.6-bookworm@sha256:d8c365d63879c2312e332cb796961f2695dd65124ceb3c0247d9c5426b7dde5f AS builder

ARG GOFLAGS=""
ENV GOFLAGS=$GOFLAGS

# Move to working directory /build
WORKDIR /build

# Copy and download dependency using go mod
COPY go.mod .
COPY go.sum .
RUN go mod download

# Copy the code into the container
COPY . .

# Build the application
RUN go build -o /build/bin/witness ./internal/witness/cmd/witness

# Build release image
FROM golang:1.21.6-bookworm@sha256:d8c365d63879c2312e332cb796961f2695dd65124ceb3c0247d9c5426b7dde5f

COPY --from=builder /build/bin/witness /bin/witness
ENTRYPOINT ["/bin/witness"]
