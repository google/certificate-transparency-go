FROM golang:1.22.6-bookworm@sha256:39b7e6ebaca464d51989858871f792f2e186dce8ce0cbdba7e88e4444b244407 AS builder

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
FROM golang:1.22.6-bookworm@sha256:39b7e6ebaca464d51989858871f792f2e186dce8ce0cbdba7e88e4444b244407

COPY --from=builder /build/bin/witness /bin/witness
ENTRYPOINT ["/bin/witness"]
