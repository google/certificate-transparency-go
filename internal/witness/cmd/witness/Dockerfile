FROM golang:buster@sha256:fd9306e1c664bd49a11d4a4a04e41303430e069e437d137876e9290a555e06fb AS builder

ARG GOFLAGS=""
ENV GOFLAGS=$GOFLAGS
ENV GO111MODULE=on

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
FROM golang:buster@sha256:fd9306e1c664bd49a11d4a4a04e41303430e069e437d137876e9290a555e06fb

COPY --from=builder /build/bin/witness /bin/witness
ENTRYPOINT ["/bin/witness"]
