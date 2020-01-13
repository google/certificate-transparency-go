# SCT Generator

This tool will create a Signed Certificate Timestamp (SCT) for a certificate, given a CT log private key, timestamp and the certificate chain (the certificate and its issuance chain, up to the root of trust).

WARNING: This should only be used for generating SCTs for test purposes.
Generating SCTs using a production CT log private key is a great way to violate
a CT log's maximum merge delay.

```shell
go run github.com/google/certificate-transparency-go/ctutil/sctgen \
  --log_private_key "encrypted_key.pem" \
  --log_private_key_password "my-password" \
  --timestamp="2020-01-01T00:00:00Z" \
  --cert_chain "my-cert-chain.pem" \
```

The SCT will be output in JSON format. If TLS format is required, use the
`--tls_out` flag to specify a file path where the TLS-encoded SCT should be
written.
