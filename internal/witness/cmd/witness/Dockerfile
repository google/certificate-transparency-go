FROM golang:1.22.4-bookworm@sha256:96788441ff71144c93fc67577f2ea99fd4474f8e45c084e9445fe3454387de5b AS builder

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
FROM golang:1.22.4-bookworm@sha256:96788441ff71144c93fc67577f2ea99fd4474f8e45c084e9445fe3454387de5b

COPY --from=builder /build/bin/witness /bin/witness
ENTRYPOINT ["/bin/witness"]
