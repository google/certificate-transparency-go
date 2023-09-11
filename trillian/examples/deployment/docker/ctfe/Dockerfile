FROM golang:1.21.1-bookworm@sha256:d3114db136e7f2d9b08c3fcd374381ba3f8d85c17b80c48dbc53cd938cfb2b64 as build

ARG GOFLAGS=""
ENV GOFLAGS=$GOFLAGS

WORKDIR /build

COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .

RUN CGO_ENABLED=0 go build ./trillian/ctfe/ct_server

FROM gcr.io/distroless/base@sha256:46c5b9bd3e3efff512e28350766b54355fce6337a0b44ba3f822ab918eca4520

COPY --from=build /build/ct_server /

ENTRYPOINT ["/ct_server"]
