FROM golang:1.21.6-bookworm@sha256:1e8ea75170ea0c4653ceab6d37dd12644d1bb44347d1bae457e5d0475d1d26c4 AS builder

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
FROM golang:1.21.6-bookworm@sha256:1e8ea75170ea0c4653ceab6d37dd12644d1bb44347d1bae457e5d0475d1d26c4

COPY --from=builder /build/bin/witness /bin/witness
ENTRYPOINT ["/bin/witness"]
