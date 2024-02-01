FROM golang:1.21.6-bookworm@sha256:69bfed39a11563b13cddf6167195e5637a14212f95fd5a4954b377c0511d2fda AS builder

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
FROM golang:1.21.6-bookworm@sha256:69bfed39a11563b13cddf6167195e5637a14212f95fd5a4954b377c0511d2fda

COPY --from=builder /build/bin/witness /bin/witness
ENTRYPOINT ["/bin/witness"]
