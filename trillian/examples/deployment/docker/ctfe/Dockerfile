FROM golang:1.21.6-bookworm@sha256:c4b696f1b2bf7d42e02b62b160c3f81c39386e1c567603df8c514ad6ce93361d as build

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
