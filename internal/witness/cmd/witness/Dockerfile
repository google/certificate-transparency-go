FROM golang:1.24.1-bookworm@sha256:d7d795d0a9f51b00d9c9bfd17388c2c626004a50c6ed7c581e095122507fe1ab AS builder

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
FROM golang:1.24.1-bookworm@sha256:d7d795d0a9f51b00d9c9bfd17388c2c626004a50c6ed7c581e095122507fe1ab

COPY --from=builder /build/bin/witness /bin/witness
ENTRYPOINT ["/bin/witness"]
