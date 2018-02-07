# Certificate Transparency: Go Code

[![Build Status](https://travis-ci.org/google/certificate-transparency-go.svg?branch=master)](https://travis-ci.org/google/certificate-transparency-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/google/certificate-transparency-go)](https://goreportcard.com/report/github.com/google/certificate-transparency-go)
[![GoDoc](https://godoc.org/github.com/google/certificate-transparency-go?status.svg)](https://godoc.org/github.com/google/certificate-transparency-go)

This repository holds Go code related to
[Certificate Transparency](https://www.certificate-transparency.org/) (CT).  The
repository requires Go version 1.9.

 - [Repository Structure](#repository-structure)
 - [Working on the Code](#working-on-the-code)
     - [Rebuilding Generated Code](#rebuilding-generated-code)
     - [Updating Vendor Code](#updating-vendor-code)
     - [Running Codebase Checks](#running-codebase-checks)

## Repository Structure

The main parts of the repository are:

 - Encoding libraries:
   - `asn1/` and `x509/` are forks of the upstream Go `encoding/asn1` and
     `crypto/x509` libraries.  We maintain separate forks of these packages
     because CT is intended to act as an observatory of certificates across the
     ecosystem; as such, we need to be able to process somewhat-malformed
     certificates that the stricter upstream code would (correctly) reject.
     Our `x509` fork also includes code for working with the
     [pre-certificates defined in RFC 6962](https://tools.ietf.org/html/rfc6962#section-3.1).
   - `tls` holds a library for processing TLS-encoded data as described in
     [RFC 5246](https://tools.ietf.org/html/rfc5246).
   - `x509util` provides additional utilities for dealing with
     `x509.Certificate`s.
 - CT client libraries:
   - The top-level `ct` package (in `.`) holds types and utilities for working
     with CT data structures defined in
     [RFC 6962](https://tools.ietf.org/html/rfc6962).
   - `client/` and `jsonclient/` hold libraries that allow access to CT Logs
     via entrypoints described in
     [section 4 of RFC 6962](https://tools.ietf.org/html/rfc6962#section-4).
   - `scanner/` holds a library for scanning the entire contents of an existing
     CT Log.
 - Command line tools:
   - `./client/ctclient` allows interaction with a CT Log
   - `./scanner/scanlog` allows an existing CT Log to be scanned for certificates
      of interest; please be polite when running this tool against a Log.
   - `./x509util/certcheck` allows display and verification of certificates
   - `./x509util/crlcheck` allows display and verification of certificate
     revocation lists (CRLs).
 - CT Personality for [Trillian](https://github.com/google/trillian):
    - `trillian/` holds code that allows a Certificate Transparency Log to be
      run using a Trillian Log as its back-end.


## Working on the Code

Developers who want to make changes to the codebase need some additional
dependencies and tools, described in the following sections.  The
[Travis configuration](.travis.yml) for the codebase is also useful reference
for the required tools and scripts, as it may be more up-to-date than this
document.

### Rebuilding Generated Code

Some of the CT Go code is autogenerated from other files:

 - [Protocol buffer](https://developers.google.com/protocol-buffers/) message
   definitions are converted to `.pb.go` implementations.
 - A mock implementation of the Trillian gRPC API is created with
   [GoMock](https://github.com/golang/mock).

Re-generating mock or protobuffer files is only needed if you're changing
the original files; if you do, you'll need to install the prerequisites:

  - `mockgen` tool from https://github.com/golang/mock
  - `protoc`, [Go support for protoc](https://github.com/golang/protobuf) (see
     documentation linked from the
     [protobuf site](https://github.com/google/protobuf))

and run the following:

```bash
go generate -x ./...  # hunts for //go:generate comments and runs them
```

### Updating Vendor Code

The codebase includes a couple of external projects under the `vendor/`
subdirectory, to ensure that builds use a fixed version (typically because the
upstream repository does not guarantee back-compatibility between the tip
`master` branch and the current stable release).  See
[instructions in the Trillian repo](https://github.com/google/trillian#updating-vendor-code)
for how to update vendored subtrees.


### Running Codebase Checks

The [`scripts/presubmit.sh`](scripts/presubmit.sh) script runs various tools
and tests over the codebase.

```bash
# Install gometalinter and all linters
go get -u github.com/alecthomas/gometalinter
gometalinter --install

# Run code generation, build, test and linters
./scripts/presubmit.sh

# Run build, test and linters but skip code generation
./scripts/presubmit.sh  --no-generate

# Or just run the linters alone:
gometalinter --config=gometalinter.json ./...
```
