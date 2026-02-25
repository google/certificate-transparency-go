FROM golang:1.26.0-bookworm@sha256:4465a2fd010308d9de86a610b56ed8ae788da5f0cf2e6ebe33d8e1f275dd2580 as build

ARG GOFLAGS=""
ENV GOFLAGS=$GOFLAGS

WORKDIR /build

COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .

RUN go build ./trillian/ctfe/ct_server

FROM gcr.io/distroless/base-debian12@sha256:937c7eaaf6f3f2d38a1f8c4aeff326f0c56e4593ea152e9e8f74d976dde52f56

COPY --from=build /build/ct_server /

ENTRYPOINT ["/ct_server"]
