FROM golang:1.23.3-bookworm@sha256:0e3377d7a71c1fcb31cdc3215292712e83baec44e4792aeaa75e503cfcae16ec AS builder

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
FROM golang:1.23.3-bookworm@sha256:0e3377d7a71c1fcb31cdc3215292712e83baec44e4792aeaa75e503cfcae16ec

COPY --from=builder /build/bin/witness /bin/witness
ENTRYPOINT ["/bin/witness"]
