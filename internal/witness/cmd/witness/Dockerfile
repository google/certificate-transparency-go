FROM golang:1.21.6-bookworm@sha256:c4b696f1b2bf7d42e02b62b160c3f81c39386e1c567603df8c514ad6ce93361d AS builder

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
FROM golang:1.21.6-bookworm@sha256:c4b696f1b2bf7d42e02b62b160c3f81c39386e1c567603df8c514ad6ce93361d

COPY --from=builder /build/bin/witness /bin/witness
ENTRYPOINT ["/bin/witness"]
