package clientv2

import (
	"fmt"
	"math/big"

	ct "github.com/google/certificate-transparency/go"
	"github.com/google/certificate-transparency/go/asn1"
	"github.com/google/certificate-transparency/go/x509/pkix"
)

// This file holds code related to the Cryptographic Message Syntax (CMS)
// defined by RFC 5652; any references to a section number refer to this
// document.

// CMSSignedData is the equivalent of the SignedData ASN.1 structure from section 5.1.
type CMSSignedData struct {
	Version          int
	DigestAlgorithms DigestAlgorithmIdentifiersSET
	EncapContentInfo EncapsulatedContentInfo
	Certificates     CertificatesSET          `asn1:"tag:0,optional"`
	CrlsSET          RevocationInfoChoicesSET `asn1:"tag:1,optional"`
	SignerInfos      SignerInfosSET
}

// The following types all have "..SET" in the type name to indicate to the asn1 encoder that they
// are SETs not SEQUENCEs.

// DigestAlgorithmIdentifiersSET is the equivalent of the DigestAlgorithmIdentifiers
// ASN.1 type from section 5.1.
type DigestAlgorithmIdentifiersSET []pkix.AlgorithmIdentifier

// CertificatesSET is the equivalent of the CertificateSet ASN.1 type from section 5.1.
type CertificatesSET []asn1.RawValue

// RevocationInfoChoicesSET is the equivalent of the RevocationInfoChoices ASN.1 type from section 5.1.
type RevocationInfoChoicesSET []asn1.RawValue

// SignerInfosSET is the equivalent of the SignerInfos ASN.1 type from section 5.1.
type SignerInfosSET []SignerInfo

// AttributesSET is the equivalent of the SignedAttributes and UnsignedAttributes ASN.1 types from section 5.3.
type AttributesSET []Attribute

// AttrValuesSET is the equivalent of the 'SET OF AttributeValue' ASN.1 type from section 5.3
type AttrValuesSET []asn1.RawValue

// EncapsulatedContentInfo is the equivalent of the EncapsulatedContentInfo ASN.1 type from section 5.2.
type EncapsulatedContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     []byte `asn1:"tag:0,explicit,optional"`
}

// SignerInfo is the equivalent of the SignerInfo ASN.1 type from section 5.3.
type SignerInfo struct {
	Version            int
	SID                SignerIdentifier
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttributes   AttributesSET `asn1:"tag:0,optional"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      AttributesSET `asn1:"tag:1,optional"`
}

// SignerIdentifier corresponds to a single variant of the ASN.1 SignerIdentifier type (which is a CHOICE), from section 5.3.
type SignerIdentifier IssuerAndSerialNumber

// IssuerAndSerialNumber is the equivalent of the IssuerAndSerialNumber ASN.1 type from section 10.2.4.
type IssuerAndSerialNumber struct {
	Issuer       pkix.RDNSequence // For a pkix.Name.
	SerialNumber *big.Int
}

// Attribute is equivalent of the Attribute ASN.1 type from section 5.3.
type Attribute struct {
	AttrType   asn1.ObjectIdentifier
	AttrValues AttrValuesSET
}

// OID value to identify the content-type attribute, from section 11.1.
var cmsContentTypeOID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}

// OID value to identify the message digest attribute, from section 11.2.
var cmsMessageDigestOID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}

// OID value to identify a pre-certificate content type, from RFC 6962-bis section 3.2.
var cmsPrecertEContentTypeOID = asn1.ObjectIdentifier{1, 3, 101, 78}

// Given that section 3.2 indicates the certificates field is omitted, and the
// eContentType is not id-data, the version algorithm of RFC 5652 section 5.1
// indicates that version 3 should be used.
const cmsExpectedVersion = 3

// CMSExtractPrecert retrieves a CMS encoded precertificate from an ASN.1
// encoded version.
func CMSExtractPrecert(precert ct.CMSPrecert) (*CMSSignedData, error) {
	var cms CMSSignedData
	rest, err := asn1.Unmarshal(precert, &cms)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CMS-encoded precert: %s", err.Error())
	} else if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data present in CMS-encoded precert")
	}
	if !cmsPrecertEContentTypeOID.Equal(cms.EncapContentInfo.EContentType) {
		return nil, fmt.Errorf("unexpected content OID %v in CMS-encoded precert", cms.EncapContentInfo.EContentType)
	}
	if len(cms.Certificates) > 0 {
		return nil, fmt.Errorf("unexpected certificates present in CMS-encoded precert")
	}
	if len(cms.SignerInfos) != 1 {
		return nil, fmt.Errorf("unexpected number (%d) of signer-infos present in CMS-encoded precert", len(cms.SignerInfos))
	}
	messageDigest := []byte{}
	seenContentType := false
	for _, attr := range cms.SignerInfos[0].SignedAttributes {
		switch {
		case cmsContentTypeOID.Equal(attr.AttrType):
			if len(attr.AttrValues) != 1 {
				return nil, fmt.Errorf("content-type attribute with unexpected number (%d) of values in CMS-encoded precert", len(attr.AttrValues))
			}
			var oid asn1.ObjectIdentifier
			rest, err := asn1.Unmarshal(attr.AttrValues[0].FullBytes, &oid)
			if err != nil {
				return nil, fmt.Errorf("failed to decode content-type OID in CMS-encoded precert")
			} else if len(rest) > 0 {
				return nil, fmt.Errorf("trailing data after content-type OID in CMS-encoded precert")
			}
			if !cmsPrecertEContentTypeOID.Equal(oid) {
				return nil, fmt.Errorf("incorrect OID %s in content-type of CMS-encoded precert", oid)
			}
			seenContentType = true
		case cmsMessageDigestOID.Equal(attr.AttrType):
			if len(attr.AttrValues) != 1 {
				return nil, fmt.Errorf("message-digest attribute with unexpected number (%d) of values in CMS-encoded precert", len(attr.AttrValues))
			}
			// TODO(drysdale): replace magic numbers with asn1.Universal/asn1.OctetString when available
			if attr.AttrValues[0].Class != 0 || attr.AttrValues[0].Tag != 4 {
				return nil, fmt.Errorf("message-digest attribute value of wrong type in CMS-encoded precert", len(attr.AttrValues))
			}
			messageDigest = attr.AttrValues[0].Bytes
		}
	}
	if len(messageDigest) == 0 {
		return nil, fmt.Errorf("missing required message-digest signedAttrs in CMS-encoded precert")
	}
	if !seenContentType {
		return nil, fmt.Errorf("missing required content-type signedAttrs in CMS-encoded precert")
	}
	return &cms, nil
}

func cmsCheckSignature(cms CMSSignedData, pubKey interface{}) error {
	// TODO(drysdale): check that the signature:
	//  - check the digest is correct for eContent
	//  - check the signature over the hash using pubKey

	return nil
}
