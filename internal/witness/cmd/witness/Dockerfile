FROM golang:1.22.0-bookworm@sha256:5a3e1698b23e1967b77493a0c4710aee36873bfdd839786a6184a94530d97709 AS builder

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
FROM golang:1.22.0-bookworm@sha256:5a3e1698b23e1967b77493a0c4710aee36873bfdd839786a6184a94530d97709

COPY --from=builder /build/bin/witness /bin/witness
ENTRYPOINT ["/bin/witness"]
