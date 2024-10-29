FROM golang:1.23.2-bookworm@sha256:2341ddffd3eddb72e0aebab476222fbc24d4a507c4d490a51892ec861bdb71fc as build

ARG GOFLAGS=""
ENV GOFLAGS=$GOFLAGS

WORKDIR /build

COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .

RUN go build ./trillian/ctfe/ct_server

FROM gcr.io/distroless/base-debian12@sha256:8fe31fb9d159141d9c3ff99f1fd287239d89d97ea95fea1f08f82ea5f2b544da

COPY --from=build /build/ct_server /

ENTRYPOINT ["/ct_server"]
