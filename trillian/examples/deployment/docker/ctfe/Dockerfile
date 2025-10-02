FROM golang:1.25.1-bookworm@sha256:916e32b41e466830cae4286075872c072d07edb5eee4dfeddfda02d0ff16a392 as build

ARG GOFLAGS=""
ENV GOFLAGS=$GOFLAGS

WORKDIR /build

COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .

RUN go build ./trillian/ctfe/ct_server

FROM gcr.io/distroless/base-debian12@sha256:fa15492938650e1a5b87e34d47dc7d99a2b4e8aefd81b931b3f3eb6bb4c1d2f6

COPY --from=build /build/ct_server /

ENTRYPOINT ["/ct_server"]
