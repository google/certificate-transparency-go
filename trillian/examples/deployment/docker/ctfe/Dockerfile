FROM golang:1.21.6-bookworm@sha256:3efef61ff1d99c8a90845100e2a7e934b4a5d11b639075dc605ff53c141044fc as build

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
