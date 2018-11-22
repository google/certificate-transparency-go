FROM golang:1.10 as build

ADD . /go/src/github.com/google/certificate-transparency-go
WORKDIR /go/src/github.com/google/certificate-transparency-go

ARG GOFLAGS=""
RUN go get ${GOFLAGS} ./trillian/ctfe/ct_server

FROM gcr.io/distroless/base

COPY --from=build /go/bin/ct_server /

ENTRYPOINT ["/ct_server"]
