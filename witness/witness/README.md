CT Witness
==============

The witness is an HTTP service that stores STHs it has seen from
a configurable list of Certificate Transparency logs in a sqlite database.  This 
is a lightweight way to help detect or even prevent split-view attacks.  An 
overview of witnessing can be found in 
[trillian-examples](https://github.com/google/trillian-examples/tree/master/witness), along with "generic" witness implementations.  This witness is designed to be 
compatible with the specific formats used by CT.

Once up and running, the witness provides three API endpoints (as defined in
[api/http.go](api/http.go)):
- `/witness/v0/logs` returns a list of all logs for which the witness is
  currently storing an STH.
- `/witness/v0/logs/<logid>/update` acts to update the STH stored for `logid`.
- `/witness/v0/logs/<logid>/sth` returns the latest STH for `logid`.

Running the witness
--------------------

Running the witness is as simple as running `go run main.go` (where `main.go`
can be found in the `cmd/witness` directory), with the following flags:
- `listen`, which specifies the address and port to listen on.
- `db_file`, which specifies the desired location of the sqlite database.  The
  use of sqlite limits the scalability and reliability of the witness (because
  this is a local file), so if that is required a different database backend
  would be needed.
- `config_file`, which specifies configuration information for the logs.  A 
  sample configuration file is at `cmd/witness/example.conf`, and in general it
  is necessary to specify the following fields for each log:
    - `logID`, which is the identifier for the log.
    - `pubKey`, which is the public key of the log.
- `private_key`, which specifies the private signing key of the witness.
