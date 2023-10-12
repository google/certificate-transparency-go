FROM golang:1.21.3-bookworm@sha256:a94b089bc5cabc71da6088eef7493e1d3cb7ffdd0cda3bf85f4aaaed45a71664 AS builder

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
FROM golang:1.21.3-bookworm@sha256:a94b089bc5cabc71da6088eef7493e1d3cb7ffdd0cda3bf85f4aaaed45a71664

COPY --from=builder /build/bin/witness /bin/witness
ENTRYPOINT ["/bin/witness"]
