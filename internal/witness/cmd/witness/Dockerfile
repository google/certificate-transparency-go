FROM golang:buster@sha256:eb3f9ac805435c1b2c965d63ce460988e1000058e1f67881324746362baf9572 AS builder

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
FROM golang:buster@sha256:eb3f9ac805435c1b2c965d63ce460988e1000058e1f67881324746362baf9572

COPY --from=builder /build/bin/witness /bin/witness
ENTRYPOINT ["/bin/witness"]
