FROM golang:1.22.1-bookworm@sha256:7f9c05839800653366fa503d21d48f245f1e60a5eb60043efa14b562fea442b6 as build

ARG GOFLAGS=""
ENV GOFLAGS=$GOFLAGS

WORKDIR /build

COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .

RUN go build ./trillian/ctfe/ct_server

FROM gcr.io/distroless/base-debian12@sha256:28a7f1fe3058f3efef4b7e5fe99f9c11d00eb09d9693b80bcb9d1f59989ba44a

COPY --from=build /build/ct_server /

ENTRYPOINT ["/ct_server"]
