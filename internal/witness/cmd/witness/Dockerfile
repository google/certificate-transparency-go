FROM golang:1.21.1-bookworm@sha256:61f84bc8cddb878258b2966d682c11a1317e97a371ff0da98823d9e326d9dac1 AS builder

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
FROM golang:1.21.1-bookworm@sha256:61f84bc8cddb878258b2966d682c11a1317e97a371ff0da98823d9e326d9dac1

COPY --from=builder /build/bin/witness /bin/witness
ENTRYPOINT ["/bin/witness"]
