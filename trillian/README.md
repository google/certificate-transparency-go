# Trillian CT Personality

This directory holds code and scripts for running a CT Log based on the
[Trillian](https://github.com/google/trillian) general transparency Log.

The main code for the CT personality is held in `trillian/ctfe`; this code
responds to HTTP requests on the
[CT API paths](https://tools.ietf.org/html/rfc6962#section-4) and translates
them to the equivalent gRPC API requests to the Trillian Log.

This obviously relies on the gRPC API definitions at
`github.com/google/trillian`; the code also uses common libraries from the
Trillian project for various things including:
 - exposing monitoring and statistics via an `interface` and corresponding
   Prometheus implementation (`github.com/google/trillian/monitoring/...`)
 - dealing with cryptographic keys (`github.com/google/trillian/crypto/...`).

The `trillian/integration/` directory holds scripts and tests for running the whole
system locally.  In particular:
 - `trillian/integration/ct_integration_test.sh` brings up local processes
   running a Trillian Log server, signer and a CT personality, and exercises the
   complete set of RFC 6962 API entrypoints.
 - `trillian/integration/ct_hammer_test.sh` brings up a complete system and runs
   a continuous randomized test of the CT entrypoints.

These scripts require a local database instance to be configured as described
in the [Trillian instructions](https://github.com/google/trillian#mysql-setup).


