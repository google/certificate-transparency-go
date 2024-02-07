FROM golang:1.22.0-bookworm@sha256:874c2677e43be36a429823f2742af85844772664f273c1c8c8235f10aba51cd3 AS builder

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
FROM golang:1.22.0-bookworm@sha256:874c2677e43be36a429823f2742af85844772664f273c1c8c8235f10aba51cd3

COPY --from=builder /build/bin/witness /bin/witness
ENTRYPOINT ["/bin/witness"]
