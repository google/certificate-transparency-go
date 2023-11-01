FROM golang:1.21.3-bookworm@sha256:5ee12963390a919952d80f1d7894c75a43467f6ab1d4204325093e62705f3609 AS builder

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
FROM golang:1.21.3-bookworm@sha256:5ee12963390a919952d80f1d7894c75a43467f6ab1d4204325093e62705f3609

COPY --from=builder /build/bin/witness /bin/witness
ENTRYPOINT ["/bin/witness"]
