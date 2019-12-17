FROM golang:1.11.13 as builder
RUN ln -fs /usr/share/zoneinfo/America/New_York /etc/localtime && dpkg-reconfigure -f noninteractive tzdata
RUN apt update -qq
RUN apt install -y unzip tree 

# install protobuffer compiler
ADD https://github.com/protocolbuffers/protobuf/releases/download/v3.5.1/protoc-3.5.1-linux-x86_64.zip /opt/protoc
ENV PATH "${PATH}:/opt/protoc/bin"

FROM builder as ct_no_deps

# install certificate transparency
RUN go get github.com/zorawar87/certificate-transparency-go
WORKDIR /go/src/github.com/zorawar87/certificate-transparency-go

# turn on go modules and resolve dependencies
FROM ct_no_deps as skeletal_ct
ENV GO111MODULE=on
RUN go install \
    github.com/golangci/golangci-lint/cmd/golangci-lint \
    github.com/golang/protobuf/proto \
    github.com/golang/protobuf/protoc-gen-go \
    github.com/golang/mock/mockgen \
    go.etcd.io/etcd \
    go.etcd.io/etcd/etcdctl

# install db integration
FROM skeletal_ct
RUN go generate && echo "Certificate Transparency Repo Setup: OK"
RUN apt install -y vim default-mysql-client-core lsof

WORKDIR /go/src/github.com/zorawar87/certificate-transparency-go/trillian
RUN go build ./...
RUN go test ./...

ENV MYSQL_HOST db
ENV MYSQL_ROOT_PASSWORD beeblebrox
RUN echo $MYSQL_HOST $MYSQL_ROOT_PASSWORD
#RUN mysql -hdb -p3306 -uroot -pbeeblebrox
#RUN ../scripts/resetctdb.sh --force --verbose
#RUN ./integration/integration_test.sh


CMD "bash"
