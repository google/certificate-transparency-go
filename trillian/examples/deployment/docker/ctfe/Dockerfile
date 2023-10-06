FROM golang:1.21.2-bookworm@sha256:a44d05d5de3474f8135462903bbf74a0fdb761aec455ff557c467339dc0b729b as build

ARG GOFLAGS=""
ENV GOFLAGS=$GOFLAGS

WORKDIR /build

COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .

RUN CGO_ENABLED=0 go build ./trillian/ctfe/ct_server

FROM gcr.io/distroless/base@sha256:a35b6525fde5572656e24109064dd147fbaedc26e5a7ccd147ff3ed3a4308c21

COPY --from=build /build/ct_server /

ENTRYPOINT ["/ct_server"]
