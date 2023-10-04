FROM golang:1.21.1-bookworm@sha256:61f84bc8cddb878258b2966d682c11a1317e97a371ff0da98823d9e326d9dac1 as build

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
