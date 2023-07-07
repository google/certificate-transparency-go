FROM alpine:3.8@sha256:82d1e9d7ed48a7523bdebc18cf6290bdb97b82302a8a9c27d4fe885949ea94d1

RUN apk add --no-cache gettext

ADD envsubst_inplace.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
