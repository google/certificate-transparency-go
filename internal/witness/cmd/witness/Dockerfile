FROM golang:1.22.1-bookworm@sha256:7a392a2537174853622ab57601d672e83f783d8314790ffe2819c95241826338 AS builder

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
FROM golang:1.22.1-bookworm@sha256:7a392a2537174853622ab57601d672e83f783d8314790ffe2819c95241826338

COPY --from=builder /build/bin/witness /bin/witness
ENTRYPOINT ["/bin/witness"]
