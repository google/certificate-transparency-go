FROM golang:1.23.4-bookworm@sha256:ef30001eeadd12890c7737c26f3be5b3a8479ccdcdc553b999c84879875a27ce as build

ARG GOFLAGS=""
ENV GOFLAGS=$GOFLAGS

WORKDIR /build

COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .

RUN go build ./trillian/ctfe/ct_server

FROM gcr.io/distroless/base-debian12@sha256:e9d0321de8927f69ce20e39bfc061343cce395996dfc1f0db6540e5145bc63a5

COPY --from=build /build/ct_server /

ENTRYPOINT ["/ct_server"]
