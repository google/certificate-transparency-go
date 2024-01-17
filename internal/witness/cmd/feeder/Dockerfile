FROM golang:1.21.6-bookworm@sha256:c4b696f1b2bf7d42e02b62b160c3f81c39386e1c567603df8c514ad6ce93361d as builder

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
RUN go build -o /build/bin/feeder ./internal/witness/cmd/feeder

# Build release image
FROM alpine@sha256:51b67269f354137895d43f3b3d810bfacd3945438e94dc5ac55fdac340352f48

COPY --from=builder /build/bin/feeder /bin/feeder
ENTRYPOINT ["/bin/feeder"]
