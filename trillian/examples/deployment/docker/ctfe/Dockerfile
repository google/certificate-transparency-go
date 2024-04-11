FROM golang:1.22.2-bookworm@sha256:3451eec734d0d3d87ea6f240d6854dd71573801157b29fbd2adc359fd0fc714c as build

ARG GOFLAGS=""
ENV GOFLAGS=$GOFLAGS

WORKDIR /build

COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .

RUN go build ./trillian/ctfe/ct_server

FROM gcr.io/distroless/base-debian12@sha256:611d30d7f6d9992c37b1e1a212eefdf1f7c671deb56db3707e24eb01da8c4c2a

COPY --from=build /build/ct_server /

ENTRYPOINT ["/ct_server"]
