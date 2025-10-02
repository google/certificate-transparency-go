FROM golang:1.25.1-bookworm@sha256:916e32b41e466830cae4286075872c072d07edb5eee4dfeddfda02d0ff16a392 AS builder

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
FROM golang:1.25.1-bookworm@sha256:916e32b41e466830cae4286075872c072d07edb5eee4dfeddfda02d0ff16a392

COPY --from=builder /build/bin/witness /bin/witness
ENTRYPOINT ["/bin/witness"]
