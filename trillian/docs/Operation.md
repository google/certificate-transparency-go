# Operating a CT Log

Once a CT log is deployed it needs to be kept operational, particularly if it
is expected to be included in Chrome's
[list of trusted logs](http://www.certificate-transparency.org/known-logs).

Be warned: running a CT log is more difficult than running a normal
database-backed web site, because of the security properties required from a Log
&ndash; running a public Log involves a commitment to reliably store all (valid)
uploaded certificates and include them in the tree within a specified period.

This means that failures that would be recoverable for a normal website &ndash;
losing tiny amounts of logged data, accidentally re-using keys &ndash; will
result in the [failure](https://tools.ietf.org/html/rfc6962#section-7.3) of a CT
Log.

 - [Key Management](#key-management)
 - [Troubleshooting](#troubleshooting)
 - [Submitting a Log](#submitting-a-log)

## Key Management

A CT Log is a cryptographic entity that signs data using a
[private key](https://tools.ietf.org/html/rfc6962#section-2.1.4).  This key is
needed by all of the distributed Log instances, but also needs to be kept
secure.  In particular:

 - The CT Log key must not be re-used for distinct Logs.
 - The CT Log key should not be re-used for HTTPS/TLS termination.

The corresponding public key is needed in order to register as a
[known log](http://www.certificate-transparency.org/known-logs)


## Troubleshooting

TODO(daviddrysdale): expand this
 - Any MySQL tools to explore the database? Safe to do so for a running log?
 - Changing logging levels? What to look for in logs, and where?
 - Backups?  turn out not to be not helpful -- restoring a database is likely
   to fork the Merkle tree.


## Submitting a Log

TODO(daviddrysdale): give pointers to instructions from Chrome.  Inputs are:
 - The URL for the Log.
 - The public key for the Log.
 - The maximum merge delay (MMD) that the Log has committed to.
 - Any temporal shard ranges.
