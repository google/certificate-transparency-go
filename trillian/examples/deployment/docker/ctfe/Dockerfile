FROM golang:buster as build

ARG GOFLAGS=""
ENV GOFLAGS=$GOFLAGS
ENV GO111MODULE=on

WORKDIR /build

COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .

RUN go build ./trillian/ctfe/ct_server

FROM gcr.io/distroless/base

COPY --from=build /build/ct_server /

ENTRYPOINT ["/ct_server"]
