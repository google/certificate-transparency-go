FROM golang:1.21.5-bookworm@sha256:a6b787c7f9046e3fdaa97bca1f76fd23ff4108f612de885e1af87e0dccc02f99 as builder

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
RUN go build -o /build/bin/feeder ./internal/witness/cmd/feeder

# Build release image
FROM alpine@sha256:34871e7290500828b39e22294660bee86d966bc0017544e848dd9a255cdf59e0

COPY --from=builder /build/bin/feeder /bin/feeder
ENTRYPOINT ["/bin/feeder"]
