FROM golang:1.21.6-bookworm@sha256:b651ed8e3316720203ec18cbf8fa16a0f30d686b0ba5207f77ca5ae10d55da77 as build

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
