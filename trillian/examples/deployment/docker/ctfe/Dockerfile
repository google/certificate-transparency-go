FROM golang:1.21.6-bookworm@sha256:69bfed39a11563b13cddf6167195e5637a14212f95fd5a4954b377c0511d2fda as build

ARG GOFLAGS=""
ENV GOFLAGS=$GOFLAGS

WORKDIR /build

COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .

RUN go build ./trillian/ctfe/ct_server

FROM gcr.io/distroless/base-debian12@sha256:f47fa3dbb9c1b1a5d968106c98380c40f28c721f0f8e598e8d760169ae2db836

COPY --from=build /build/ct_server /

ENTRYPOINT ["/ct_server"]
