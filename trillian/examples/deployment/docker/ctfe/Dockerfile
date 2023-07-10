FROM golang:buster@sha256:fd9306e1c664bd49a11d4a4a04e41303430e069e437d137876e9290a555e06fb as build

ARG GOFLAGS=""
ENV GOFLAGS=$GOFLAGS

WORKDIR /build

COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .

RUN go build ./trillian/ctfe/ct_server

FROM gcr.io/distroless/base@sha256:73deaaf6a207c1a33850257ba74e0f196bc418636cada9943a03d7abea980d6d

COPY --from=build /build/ct_server /

ENTRYPOINT ["/ct_server"]
