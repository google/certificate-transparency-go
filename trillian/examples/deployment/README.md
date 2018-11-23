# Deploying CTFE (Certificate Transparency FrontEnd)

## Setup

### Clone Source

Both build and example deployment files are stored within this repo. For any of
the below deployment methods, start by cloning the repo.

```shell
git clone https://github.com/google/certificate-transparency-go.git/
cd certificate-transparency-go
```

## Local Deployments

### Run with Docker Compose

For simple deployments, running in a container is an easy way to get up and
running with a local database. To use Docker to run and interact with CTFE,
start here.

#### Start Trillian

First, you need to have Trillian installed and running locally. If you don't
already have this, look at
[the instructions in the Trillian repo](https://github.com/google/trillian/blob/master/examples/deployment/README.md#local-deployments).

#### Create a new log in Trillian

First, you need a log (an append-only Merkle tree) hosted by Trillian. Create
one using the following commands:

```shell
go get github.com/google/trillian/cmd/createtree
LOG_ID=$(createtree --admin-server=localhost:8090)
```

Now, copy the value of `$LOG_ID` into the [ct_server.cfg](ct_server.cfg) file,
replacing the existing value of `log_id`. The following command will do this:

```shell
sed -i -r "s/log_id: [[:digit:]]+/log_id: ${LOG_ID}/" ct_server.cfg
```

Now you can start the CTFE:

```shell
docker-compose -f docker-compose.yml up
```

By default, the only CT log will be called "test" and will be accessible at
https://localhost:6962/test/ct/v1/. Its only trusted roots are those found in
the [testdata directory](../../testdata). You can change this by modifying the
[roots.pem](roots.pem) file and restarting the CTFE.
