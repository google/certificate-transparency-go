FROM golang:1.24.4-bookworm@sha256:8faa537d0690017d8000e38e1ed9ed4c5990d40a3022ce2596a825c6c87f62c4 as build

ARG GOFLAGS=""
ENV GOFLAGS=$GOFLAGS

WORKDIR /build

COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .

RUN go build ./trillian/ctfe/ct_server

FROM gcr.io/distroless/base-debian12@sha256:201ef9125ff3f55fda8e0697eff0b3ce9078366503ef066653635a3ac3ed9c26

COPY --from=build /build/ct_server /

ENTRYPOINT ["/ct_server"]
