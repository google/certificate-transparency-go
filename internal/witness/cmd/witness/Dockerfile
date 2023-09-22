FROM golang:1.21.1-bookworm@sha256:114b9cc39f435cfc34e2d48d0cb12cba2015a87f359f5dbf3ee3b6cf3591b7fb AS builder

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
FROM golang:1.21.1-bookworm@sha256:114b9cc39f435cfc34e2d48d0cb12cba2015a87f359f5dbf3ee3b6cf3591b7fb

COPY --from=builder /build/bin/witness /bin/witness
ENTRYPOINT ["/bin/witness"]
