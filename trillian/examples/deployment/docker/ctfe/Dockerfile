FROM golang:1.23.6-bookworm@sha256:441f59f8a2104b99320e1f5aaf59a81baabbc36c81f4e792d5715ef09dd29355 as build

ARG GOFLAGS=""
ENV GOFLAGS=$GOFLAGS

WORKDIR /build

COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .

RUN go build ./trillian/ctfe/ct_server

FROM gcr.io/distroless/base-debian12@sha256:74ddbf52d93fafbdd21b399271b0b4aac1babf8fa98cab59e5692e01169a1348

COPY --from=build /build/ct_server /

ENTRYPOINT ["/ct_server"]
