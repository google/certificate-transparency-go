FROM golang:1.22.2-bookworm@sha256:3451eec734d0d3d87ea6f240d6854dd71573801157b29fbd2adc359fd0fc714c AS builder

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
FROM golang:1.22.2-bookworm@sha256:3451eec734d0d3d87ea6f240d6854dd71573801157b29fbd2adc359fd0fc714c

COPY --from=builder /build/bin/witness /bin/witness
ENTRYPOINT ["/bin/witness"]
