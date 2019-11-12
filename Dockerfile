FROM golang:1.11.13

RUN ln -fs /usr/share/zoneinfo/America/New_York /etc/localtime && dpkg-reconfigure -f noninteractive tzdata

RUN apt update -qq && apt upgrade -y
RUN apt install -qq unzip tree

# install protobuffer compiler
WORKDIR /opt/protoc
RUN wget -q https://github.com/protocolbuffers/protobuf/releases/download/v3.5.1/protoc-3.5.1-linux-x86_64.zip
RUN unzip -qq protoc-3.5.1-linux-x86_64.zip

ENV PATH "${PATH}:/opt/protoc/bin"

# install certificate transparency
WORKDIR /go/src
RUN go get github.com/zorawar87/certificate-transparency-go
WORKDIR /go/src/github.com/zorawar87/certificate-transparency-go

# turn on go modules and resolve dependencies
ENV GO111MODULE=on
RUN go install \
    github.com/golangci/golangci-lint/cmd/golangci-lint \
    github.com/golang/protobuf/proto \
    github.com/golang/protobuf/protoc-gen-go \
    github.com/golang/mock/mockgen \
    go.etcd.io/etcd \
    go.etcd.io/etcd/etcdctl

RUN go generate
