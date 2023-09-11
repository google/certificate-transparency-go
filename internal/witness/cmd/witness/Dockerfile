FROM golang:1.21.1-bookworm@sha256:d3114db136e7f2d9b08c3fcd374381ba3f8d85c17b80c48dbc53cd938cfb2b64 AS builder

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
FROM golang:1.21.1-bookworm@sha256:d3114db136e7f2d9b08c3fcd374381ba3f8d85c17b80c48dbc53cd938cfb2b64

COPY --from=builder /build/bin/witness /bin/witness
ENTRYPOINT ["/bin/witness"]
