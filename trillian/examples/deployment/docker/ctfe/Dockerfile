FROM golang:1.21.3-bookworm@sha256:20f9ab52a8c3598ef13f86c9bc3b94db400e13df115ecacd8c3dfd0c0f060208 as build

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
