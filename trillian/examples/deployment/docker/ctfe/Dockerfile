FROM golang:1.21.3-bookworm@sha256:a94b089bc5cabc71da6088eef7493e1d3cb7ffdd0cda3bf85f4aaaed45a71664 as build

ARG GOFLAGS=""
ENV GOFLAGS=$GOFLAGS

WORKDIR /build

COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .

RUN CGO_ENABLED=0 go build ./trillian/ctfe/ct_server

FROM gcr.io/distroless/base@sha256:b31a6e02605827e77b7ebb82a0ac9669ec51091edd62c2c076175e05556f4ab9

COPY --from=build /build/ct_server /

ENTRYPOINT ["/ct_server"]
