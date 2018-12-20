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

Now, copy the value of `$LOG_ID` into the
[ct_server.cfg.example](ct_server.cfg.example) file, replacing the existing
value of `log_id`. The following command will do this:

```shell
sed -i -r "s/log_id: [[:digit:]]+/log_id: ${LOG_ID}/" ct_server.cfg.example
```

#### Keys

The [private key](../../testdata/ct-http-server.privkey.pem) to be used for
signing STHs and SCTs, and the corresponding
[public key](../../testdata/ct-http-server.pubkey.pem), are also present in
[ct_server.cfg.example](ct_server.cfg.example). If the CT log is to be used for
anything other than local testing, the example keys should be replaced with keys
you generate yourself.

#### Start the CTFE

Now you can start the CTFE:

```shell
docker-compose -f docker-compose.yml up
```

By default, the only CT log will be called "test" and will be accessible at
http://localhost:6962/test/ct/v1/. Its only trusted roots are those found in the
[testdata directory](../../testdata). You can change this by modifying the
[roots.pem](roots.pem) file and restarting the CTFE.

#### Testing the CTFE

Assuming you didn't remove the test root from [roots.pem](roots.pem) or change
the keys in [ct_server.cfg.example](ct_server.cfg.example), the following
command should succeed in adding the very first certificate to your new CT log:

```shell
go run github.com/google/certificate-transparency-go/client/ctclient \
   --log_uri "http://localhost:6962/test" \
   --pub_key "../../testdata/ct-http-server.pubkey.pem" \
   --cert_chain "../../testdata/leaf01.chain" \
   upload
```
