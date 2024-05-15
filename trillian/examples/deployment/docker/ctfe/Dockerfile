FROM golang:1.22.3-bookworm@sha256:ef27a3c07e6727d445fc70cd861f8f29f9152e51473ee3a952ea6bddd24ebf90 as build

ARG GOFLAGS=""
ENV GOFLAGS=$GOFLAGS

WORKDIR /build

COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .

RUN go build ./trillian/ctfe/ct_server

FROM gcr.io/distroless/base-debian12@sha256:786007f631d22e8a1a5084c5b177352d9dcac24b1e8c815187750f70b24a9fc6

COPY --from=build /build/ct_server /

ENTRYPOINT ["/ct_server"]
