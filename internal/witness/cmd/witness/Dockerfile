FROM golang:1.21.1-bookworm@sha256:9c7ea4a4924ae24913401af45c9b6f439d0f782267584738d1cc1099d8b7a02c AS builder

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
FROM golang:1.21.1-bookworm@sha256:9c7ea4a4924ae24913401af45c9b6f439d0f782267584738d1cc1099d8b7a02c

COPY --from=builder /build/bin/witness /bin/witness
ENTRYPOINT ["/bin/witness"]
