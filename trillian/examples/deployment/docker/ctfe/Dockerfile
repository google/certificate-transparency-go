FROM golang:1.21.5-bookworm@sha256:2d3b13c2a6368032e9697e64e7c923184e6e3be03cf01eadff27de124114e64e as build

ARG GOFLAGS=""
ENV GOFLAGS=$GOFLAGS

WORKDIR /build

COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .

RUN go build ./trillian/ctfe/ct_server

FROM gcr.io/distroless/base-debian12@sha256:8a0bb635ccf4cfa88b2bae707c82e633d0867b77827054ed146ad5e13e35ce79

COPY --from=build /build/ct_server /

ENTRYPOINT ["/ct_server"]
