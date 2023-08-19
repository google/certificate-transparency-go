FROM golang:1.19-alpine@sha256:470c8d0638c5b7007a6118baee531c30e0516a18e45b35bff1f8ab92cf8f896d AS builder

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
FROM alpine@sha256:7144f7bab3d4c2648d7e59409f15ec52a18006a128c733fcff20d3a4a54ba44a

COPY --from=builder /build/bin/feeder /bin/feeder
ENTRYPOINT ["/bin/feeder"]
