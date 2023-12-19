FROM golang:1.21.5-bookworm@sha256:2bc6f407749746aceaeda177628872c15ae0bbe059fb504403921f2cc00f9fe1 AS builder

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
FROM golang:1.21.5-bookworm@sha256:2bc6f407749746aceaeda177628872c15ae0bbe059fb504403921f2cc00f9fe1

COPY --from=builder /build/bin/witness /bin/witness
ENTRYPOINT ["/bin/witness"]
