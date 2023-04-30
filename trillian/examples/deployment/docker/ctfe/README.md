# Dockerized Test Deployment

This brings up a CTFE with its own trillian instance and DB server for users to
get a feel for how deploying CTFE works. This is not recommended as a way of
serving production logs!

## Requirements

- Docker and Docker Compose Plugin
- go tooling
- git checkouts of:
  - github.com/google/trillian
  - github.com/google/certificate-transparency-go

The instructions below assume you've checked out the repositories within
`~/git/`, but if you have them in another location then just use a different
path when you run the command.

## Deploying

We will use 2 terminal sessions to the machine you will use for hosting the
docker containers. Each of the code stanzas below will state which terminal to
use. This makes it easier to see output logs and to avoid repeatedly changing
directory.

First bring up the trillian instance and the database:

```bash
# Terminal 1
cd ~/git/certificate-transparency-go/trillian/examples/deployment/docker/ctfe/
docker compose up
```

This brings up everything except the CTFE. Now to provision the logs.

```bash
# Terminal 2
cd ~/git/trillian/
docker exec -i ctfe-db mysql -pzaphod -Dtest < ./storage/mysql/schema/storage.sql
```

The CTFE requires some configuration files. First prepare a directory containing
these, and expose it as a docker volume. These instructions prepare this config
at `/tmp/ctfedocker` but if you plan on keeping this test instance alive for
more than a few hours then pick a less temporary location on your filesystem.

```bash
# Terminal 2
CTFE_CONF_DIR=/tmp/ctfedocker
mkdir ${CTFE_CONF_DIR}
TREE_ID=$(go run github.com/google/trillian/cmd/createtree@master --admin_server=localhost:8090)
sed "s/@TREE_ID@/$TREE_ID/" ~/git/certificate-transparency-go/trillian/examples/deployment/docker/ctfe/ct_server.cfg > ${CTFE_CONF_DIR}/ct_server.cfg
cp ./trillian/testdata/fake-ca.cert ${CTFE_CONF_DIR}
docker volume create --driver local --opt type=none --opt device=${CTFE_CONF_DIR} --opt o=bind ctfe_config
```

Now that this configuration is available, you can bring up the CTFE:

```bash
# Terminal 1
<Ctrl C> # kill the previous docker compose up command
docker compose --profile frontend up
```

This will bring up the whole stack. Assuming there are no errors in the log,
then the following command should return tree head for tree size 0.

```bash
# Terminal 2
cd ~/git/certificate-transparency-go
go run ./client/ctclient get-sth --log_uri http://localhost:8080/testlog
```

