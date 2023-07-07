FROM golang:buster@sha256:eb3f9ac805435c1b2c965d63ce460988e1000058e1f67881324746362baf9572 as build

ARG GOFLAGS=""
ENV GOFLAGS=$GOFLAGS
ENV GO111MODULE=on

WORKDIR /build

COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .

RUN go build ./trillian/ctfe/ct_server

FROM gcr.io/distroless/base@sha256:73deaaf6a207c1a33850257ba74e0f196bc418636cada9943a03d7abea980d6d

COPY --from=build /build/ct_server /

ENTRYPOINT ["/ct_server"]
