package preload

import (
	"github.com/google/certificate-transparency/go/client"
)

type AddedCert struct {
	CertDER                    client.ASN1Cert
	SignedCertificateTimestamp client.SignedCertificateTimestamp
	AddedOk                    bool
	ErrorMessage               string
}
