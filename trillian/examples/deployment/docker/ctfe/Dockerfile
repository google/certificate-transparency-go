FROM golang:1.11 as build

ADD . /go/src/github.com/google/certificate-transparency-go
WORKDIR /go/src/github.com/google/certificate-transparency-go

ARG GOFLAGS=""
ENV GOFLAGS=$GOFLAGS
ARG GO111MODULE=auto
ENV GO111MODULE=$GO111MODULE
RUN go get ./trillian/ctfe/ct_server

FROM gcr.io/distroless/base

COPY --from=build /go/bin/ct_server /

ENTRYPOINT ["/ct_server"]
