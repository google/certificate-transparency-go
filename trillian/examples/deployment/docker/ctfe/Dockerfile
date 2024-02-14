FROM golang:1.22.0-bookworm@sha256:5a3e1698b23e1967b77493a0c4710aee36873bfdd839786a6184a94530d97709 as build

ARG GOFLAGS=""
ENV GOFLAGS=$GOFLAGS

WORKDIR /build

COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .

RUN go build ./trillian/ctfe/ct_server

FROM gcr.io/distroless/base-debian12@sha256:2102ce121ff1448316b93c5f347118a8e604f5ba7ec9dd7a5c2d8b0eac2941fe

COPY --from=build /build/ct_server /

ENTRYPOINT ["/ct_server"]
