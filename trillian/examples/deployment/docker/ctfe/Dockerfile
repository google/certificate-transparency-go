FROM golang:1.22.5-bookworm@sha256:6c2780255bb7b881e904e303be0d7a079054160b2ce1efde446693c0850a39ad as build

ARG GOFLAGS=""
ENV GOFLAGS=$GOFLAGS

WORKDIR /build

COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .

RUN go build ./trillian/ctfe/ct_server

FROM gcr.io/distroless/base-debian12@sha256:1aae189e3baecbb4044c648d356ddb75025b2ba8d14cdc9c2a19ba784c90bfb9

COPY --from=build /build/ct_server /

ENTRYPOINT ["/ct_server"]
