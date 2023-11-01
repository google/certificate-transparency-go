FROM golang:1.21.3-bookworm@sha256:5ee12963390a919952d80f1d7894c75a43467f6ab1d4204325093e62705f3609 as build

ARG GOFLAGS=""
ENV GOFLAGS=$GOFLAGS

WORKDIR /build

COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .

RUN CGO_ENABLED=0 go build ./trillian/ctfe/ct_server

FROM gcr.io/distroless/base@sha256:b31a6e02605827e77b7ebb82a0ac9669ec51091edd62c2c076175e05556f4ab9

COPY --from=build /build/ct_server /

ENTRYPOINT ["/ct_server"]
