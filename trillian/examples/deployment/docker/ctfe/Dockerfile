FROM golang:1.21.4-bookworm@sha256:dadce81d7b2517bef188b89d3df3288780f87f24903c2607fb39c93a21d5365c as build

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
