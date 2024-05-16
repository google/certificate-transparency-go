FROM golang:1.22.3-bookworm@sha256:ef27a3c07e6727d445fc70cd861f8f29f9152e51473ee3a952ea6bddd24ebf90 AS builder

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
FROM golang:1.22.3-bookworm@sha256:ef27a3c07e6727d445fc70cd861f8f29f9152e51473ee3a952ea6bddd24ebf90

COPY --from=builder /build/bin/witness /bin/witness
ENTRYPOINT ["/bin/witness"]
