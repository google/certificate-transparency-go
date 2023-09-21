FROM golang:1.21.1-bookworm@sha256:114b9cc39f435cfc34e2d48d0cb12cba2015a87f359f5dbf3ee3b6cf3591b7fb as build

ARG GOFLAGS=""
ENV GOFLAGS=$GOFLAGS

WORKDIR /build

COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .

RUN CGO_ENABLED=0 go build ./trillian/ctfe/ct_server

FROM gcr.io/distroless/base@sha256:46c5b9bd3e3efff512e28350766b54355fce6337a0b44ba3f822ab918eca4520

COPY --from=build /build/ct_server /

ENTRYPOINT ["/ct_server"]
