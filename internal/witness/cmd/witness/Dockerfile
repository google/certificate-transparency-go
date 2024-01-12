FROM golang:1.21.6-bookworm@sha256:cbee5d27649be9e3a48d4d152838901c65d7f8e803f4cc46b53699dd215b555f AS builder

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
FROM golang:1.21.6-bookworm@sha256:cbee5d27649be9e3a48d4d152838901c65d7f8e803f4cc46b53699dd215b555f

COPY --from=builder /build/bin/witness /bin/witness
ENTRYPOINT ["/bin/witness"]
