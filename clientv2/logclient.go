package clientv2

import (
	"crypto"
	"errors"
	"fmt"
	"hash"
	"net/http"

	ct "github.com/google/certificate-transparency/go"
	"github.com/google/certificate-transparency/go/jsonclient"
	"github.com/google/certificate-transparency/go/tls"
	"github.com/google/certificate-transparency/go/x509"
	"golang.org/x/net/context"
)

// This code is based on draft-ietf-trans-rfc6962-bis-19.txt; any
// references to a section number on its own refer to this document.

// Options provides configuration options when constructing a LogClient instance.
type Options struct {
	jsonclient.Options
	hashAlgo tls.HashAlgorithm
}

// LogClient represents a client for a given v2 CT Log instance.
type LogClient struct {
	jsonclient.JSONClient
	hasher hash.Hash
}

// New constructs a new LogClient instance for interaction with a v2
// Certificate Transparency Log.
func New(uri string, hc *http.Client, opts Options) (*LogClient, error) {
	hasher, err := hasherForAlgorithm(opts.hashAlgo)
	if err != nil {
		return nil, err
	}
	logClient, err := jsonclient.New(uri, hc, opts.Options)
	if err != nil {
		return nil, err
	}
	return &LogClient{*logClient, hasher}, nil
}

func hasherForAlgorithm(hashAlgo tls.HashAlgorithm) (hash.Hash, error) {
	switch hashAlgo {
	case tls.SHA256:
		// SHA256 is the only allowed hash algorithm, see section 12.3.
		return crypto.SHA256.New(), nil
	default:
		return nil, fmt.Errorf("unsupported hash algorithm %d for Log", hashAlgo)
	}
}

// AddChain adds the provided chain of (DER-encoded) X.509 certificates to the Log.
func (c *LogClient) AddChain(ctx context.Context, chain []ct.ASN1Cert) (*ct.SignedCertificateTimestampDataV2, error) {
	if len(chain) == 0 {
		return nil, errors.New("no certificate provided")
	}
	req := ct.AddChainV2Request{Chain: chain}
	var rsp ct.AddChainV2Response
	if _, err := c.PostAndParseWithRetry(ctx, ct.AddChainPathV2, req, &rsp); err != nil {
		return nil, err
	}
	if rsp.SCT.VersionedType != ct.X509SCTV2 {
		return nil, fmt.Errorf("received unexpected TransItem type %d not X509SCTV2(%d)", rsp.SCT.VersionedType, ct.X509SCTV2)
	}
	result := rsp.SCT.X509SCTV2Data
	if err := checkSCTExtensions(result.SCTExtensions); err != nil {
		return nil, err
	}

	if c.Verifier != nil {
		// result.Signature is over a TransItem of type X509EntryV2.
		cert, err := x509.ParseCertificate(chain[0].Data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse leaf certificate: %s", err.Error())
		}
		if len(chain) < 2 {
			return nil, fmt.Errorf("cannot validate as issuer key unavailable for %s", cert.Issuer)
		}
		issuerCert, err := x509.ParseCertificate(chain[1].Data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse issuer certificate: %s", err.Error())
		}
		keyHash := c.hasher.Sum(issuerCert.RawSubjectPublicKeyInfo)
		signedData := ct.TransItem{
			VersionedType: ct.X509EntryV2,
			X509EntryV2Data: &ct.TimestampedCertificateEntryDataV2{
				Timestamp:      result.Timestamp,
				IssuerKeyHash:  keyHash,
				TBSCertificate: cert.RawTBSCertificate,
				SCTExtensions:  result.SCTExtensions,
			},
		}
		// TLS-encode the TransItem
		data, err := tls.Marshal(signedData)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal data for signature check: %s", err.Error())
		}
		if err := c.Verifier.VerifySignature(data, result.Signature); err != nil {
			return nil, fmt.Errorf("failed to verify SCT signature: %s", err.Error())
		}
	}
	return result, nil
}

// AddPreChain adds the provided precertificate to the Log, where precert is a
// DER-encoded CMS SignedData structure filled out as described in section 3.2,
// and chain is a list (DER-encoded) X.509 certificates needed to validate the
// precertificate.
func (c *LogClient) AddPreChain(ctx context.Context, precert ct.CMSPrecert, chain []ct.ASN1Cert) (*ct.SignedCertificateTimestampDataV2, error) {
	if len(chain) == 0 {
		return nil, errors.New("no issuer certificate provided")
	}
	// Check the CMS data is valid.
	parsedPrecert, err := CMSExtractPrecert(precert)
	if err != nil {
		return nil, err
	}
	issuerCert, err := x509.ParseCertificate(chain[0].Data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse issuer certificate: %s", err.Error())
	}
	err = cmsCheckSignature(*parsedPrecert, issuerCert.PublicKey)
	if err != nil {
		return nil, err
	}
	req := ct.AddPreChainV2Request{Precertificate: precert, Chain: chain}
	var rsp ct.AddPreChainV2Response
	if _, err := c.PostAndParseWithRetry(ctx, ct.AddPreChainPathV2, req, &rsp); err != nil {
		return nil, err
	}
	if rsp.SCT.VersionedType != ct.PrecertSCTV2 {
		return nil, fmt.Errorf("received unexpected TransItem type %d not X509SCTV2(%d)", rsp.SCT.VersionedType, ct.PrecertSCTV2)
	}

	result := rsp.SCT.X509SCTV2Data
	if err := checkSCTExtensions(result.SCTExtensions); err != nil {
		return nil, err
	}

	if c.Verifier != nil {
		// result.Signature is over a TransItem of type PrecertEntryV2.
		keyHash := c.hasher.Sum(issuerCert.RawSubjectPublicKeyInfo)
		signedData := ct.TransItem{
			VersionedType: ct.PrecertEntryV2,
			PrecertEntryV2Data: &ct.TimestampedCertificateEntryDataV2{
				Timestamp:      result.Timestamp,
				IssuerKeyHash:  keyHash,
				TBSCertificate: parsedPrecert.EncapContentInfo.EContent,
				SCTExtensions:  result.SCTExtensions,
			},
		}
		// TLS-encode the TransItem
		data, err := tls.Marshal(signedData)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal data for signature check: %s", err.Error())
		}
		if err := c.Verifier.VerifySignature(data, result.Signature); err != nil {
			return nil, fmt.Errorf("failed to verify SCT signature: %s", err.Error())
		}
	}
	return result, nil
}

// GetSTH retrieves the signed tree head (STH) of the log, as described in section 3.3.
func (c *LogClient) GetSTH(ctx context.Context) (*ct.SignedTreeHeadDataV2, error) {
	var rsp ct.GetSTHV2Response
	if _, err := c.GetAndParse(ctx, ct.GetSTHPathV2, nil, &rsp); err != nil {
		return nil, err
	}
	if rsp.STH.VersionedType != ct.SignedTreeHeadV2 {
		return nil, fmt.Errorf("received unexpected TransItem type %d not SignedTreeHeadV2(%d)", rsp.STH.VersionedType, ct.SignedTreeHeadV2)
	}
	result := rsp.STH.SignedTreeHeadV2Data
	if c.Verifier != nil {
		// result.Signature is over the TLS encoding of result.TreeHead
		data, err := tls.Marshal(result.TreeHead)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal data for signature check: %s", err.Error())
		}
		if err := c.Verifier.VerifySignature(data, result.Signature); err != nil {
			return nil, fmt.Errorf("failed to verify STH signature: %s", err.Error())
		}

	}
	return result, nil
}

// TODO(drysdale): all the other entrypoints

// Check extensions are sane.
func checkSCTExtensions(exts []ct.SCTExtension) error {
	lastExtType := -1
	for _, ext := range exts {
		extType := int(ext.SCTExtensionType)
		if extType <= lastExtType {
			return fmt.Errorf("SCT extensions not ordered correctly, %d then %d", lastExtType, extType)
		}
		lastExtType = extType
	}
	return nil
}
