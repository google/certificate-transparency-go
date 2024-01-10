FROM golang:1.21.5-bookworm@sha256:2d3b13c2a6368032e9697e64e7c923184e6e3be03cf01eadff27de124114e64e as build

ARG GOFLAGS=""
ENV GOFLAGS=$GOFLAGS

WORKDIR /build

COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .

RUN go build ./trillian/ctfe/ct_server

FROM gcr.io/distroless/base-debian12@sha256:0a93daa199e7c6e387cea8cf03fac676146735caf6965d276d86ebd3a441f27e

COPY --from=build /build/ct_server /

ENTRYPOINT ["/ct_server"]
