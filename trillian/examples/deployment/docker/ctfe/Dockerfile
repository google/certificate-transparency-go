FROM golang:1.23.1-bookworm@sha256:1a5326b07cbab12f4fd7800425f2cf25ff2bd62c404ef41b56cb99669a710a83 as build

ARG GOFLAGS=""
ENV GOFLAGS=$GOFLAGS

WORKDIR /build

COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .

RUN go build ./trillian/ctfe/ct_server

FROM gcr.io/distroless/base-debian12@sha256:88e0a2ac7c9b54f1ef941e7978c21fd45b46cc6e768f4bc28f3618a51438dc5d

COPY --from=build /build/ct_server /

ENTRYPOINT ["/ct_server"]
