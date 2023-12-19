FROM golang:1.21.5-bookworm@sha256:2bc6f407749746aceaeda177628872c15ae0bbe059fb504403921f2cc00f9fe1 as build

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
