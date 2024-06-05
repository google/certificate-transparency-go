FROM golang:1.22.4-bookworm@sha256:aec47843e52fee4436bdd3ce931417fa980e9055658b5142140925eea3044bea AS builder

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
FROM golang:1.22.4-bookworm@sha256:aec47843e52fee4436bdd3ce931417fa980e9055658b5142140925eea3044bea

COPY --from=builder /build/bin/witness /bin/witness
ENTRYPOINT ["/bin/witness"]
