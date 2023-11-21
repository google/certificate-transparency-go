FROM golang:1.21.4-bookworm@sha256:dadce81d7b2517bef188b89d3df3288780f87f24903c2607fb39c93a21d5365c AS builder

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
FROM golang:1.21.4-bookworm@sha256:dadce81d7b2517bef188b89d3df3288780f87f24903c2607fb39c93a21d5365c

COPY --from=builder /build/bin/witness /bin/witness
ENTRYPOINT ["/bin/witness"]
