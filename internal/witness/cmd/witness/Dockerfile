FROM golang:1.21.1-bookworm@sha256:a0b3bc435cf2118e62db49d611bcdfa87a525be6fdf49179a5c9dbd4d0f1c63f AS builder

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
FROM golang:1.21.1-bookworm@sha256:a0b3bc435cf2118e62db49d611bcdfa87a525be6fdf49179a5c9dbd4d0f1c63f

COPY --from=builder /build/bin/witness /bin/witness
ENTRYPOINT ["/bin/witness"]
