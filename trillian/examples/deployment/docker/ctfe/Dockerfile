FROM golang:1.21.3-bookworm@sha256:5bafbbb109f02aaf6b41ddc19f54919773c3006f1cbda1599112603367642f0e as build

ARG GOFLAGS=""
ENV GOFLAGS=$GOFLAGS

WORKDIR /build

COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .

RUN go build ./trillian/ctfe/ct_server

FROM gcr.io/distroless/base-debian12@sha256:1dfdb5ed7d9a66dcfc90135b25a46c25a85cf719b619b40c249a2445b9d055f5

COPY --from=build /build/ct_server /

ENTRYPOINT ["/ct_server"]
