FROM golang:1.22.2-bookworm@sha256:d0902bacefdde1cf45528c098d14e55d78c107def8a22d148eabd71582d7a99f as build

ARG GOFLAGS=""
ENV GOFLAGS=$GOFLAGS

WORKDIR /build

COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .

RUN go build ./trillian/ctfe/ct_server

FROM gcr.io/distroless/base-debian12@sha256:611d30d7f6d9992c37b1e1a212eefdf1f7c671deb56db3707e24eb01da8c4c2a

COPY --from=build /build/ct_server /

ENTRYPOINT ["/ct_server"]
