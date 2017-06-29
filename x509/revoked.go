// Copyright 2017 Google Inc. All Rights Reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"bytes"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/google/certificate-transparency-go/asn1"
	"github.com/google/certificate-transparency-go/x509/pkix"
)

var (
	// OID values for CRL extensions (TBSCertList.Extensions), RFC 5280 s5.2.
	OIDExtensionCRLNumber                = asn1.ObjectIdentifier{2, 5, 29, 20}
	OIDExtensionDeltaCRLIndicator        = asn1.ObjectIdentifier{2, 5, 29, 27}
	OIDExtensionIssuingDistributionPoint = asn1.ObjectIdentifier{2, 5, 29, 28}
	// OID values for CRL entry extensions (RevokedCertificate.Extensions), RFC 5280 s5.3
	OIDExtensionCRLReasons        = asn1.ObjectIdentifier{2, 5, 29, 21}
	OIDExtensionInvalidityDate    = asn1.ObjectIdentifier{2, 5, 29, 24}
	OIDExtensionCertificateIssuer = asn1.ObjectIdentifier{2, 5, 29, 29}
)

// RevocationReasonCode represents the reason for a certificate revocation; see RFC 5280 s5.3.1.
type RevocationReasonCode asn1.Enumerated

// RevocationReasonCode values.
var (
	Unspecified          = RevocationReasonCode(0)
	KeyCompromise        = RevocationReasonCode(1)
	CACompromise         = RevocationReasonCode(2)
	AffiliationChanged   = RevocationReasonCode(3)
	Superseded           = RevocationReasonCode(4)
	CessationOfOperation = RevocationReasonCode(5)
	CertificateHold      = RevocationReasonCode(6)
	RemoveFromCRL        = RevocationReasonCode(8)
	PrivilegeWithdrawn   = RevocationReasonCode(9)
	AACompromise         = RevocationReasonCode(10)
)

// ReasonFlag holds a bitmask of applicable revocation reasons, from RFC 5280 s4.2.1.13
type ReasonFlag int

// ReasonFlag values.
const (
	UnusedFlag ReasonFlag = 1 << iota
	KeyCompromiseFlag
	CACompromiseFlag
	AffiliationChangedFlag
	SupersededFlag
	CessationOfOperationFlag
	CertificateHoldFlag
	PrivilegeWithdrawnFlag
	AACompromiseFlag
)

// CertificateList represents the ASN.1 structure of the same name from RFC 5280, s5.1.
// It has the same content as pkix.CertificateList, but the contents include parsed versions
// of any extensions.
type CertificateList struct {
	Raw                asn1.RawContent
	TBSCertList        TBSCertList
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

// ExpiredAt reports whether now is past the expiry time of certList.
func (certList *CertificateList) ExpiredAt(now time.Time) bool {
	return now.After(certList.TBSCertList.NextUpdate)
}

// Indication of whether extensions need to be critical or non-critical. Extensions that
// can be either are omitted from the map.
var listExtCritical = map[string]bool{
	// From RFC 5280...
	OIDExtensionAuthorityKeyId.String():           false, // s5.2.1
	OIDExtensionIssuerAltName.String():            false, // s5.2.2
	OIDExtensionCRLNumber.String():                false, // s5.2.3
	OIDExtensionDeltaCRLIndicator.String():        true,  // s5.2.4
	OIDExtensionIssuingDistributionPoint.String(): true,  // s5.2.5
	OIDExtensionFreshestCRL.String():              false, // s5.2.6
	OIDExtensionAuthorityInfoAccess.String():      false, // s5.2.7
}

var certExtCritical = map[string]bool{
	// From RFC 5280...
	OIDExtensionCRLReasons.String():        false, // s5.3.1
	OIDExtensionInvalidityDate.String():    false, // s5.3.2
	OIDExtensionCertificateIssuer.String(): true,  // s5.3.3
}

// IssuingDistributionPoint represents the ASN.1 structure of the same
// name
type IssuingDistributionPoint struct {
	DistributionPoint          distributionPointName `asn1:"optional,tag:0"`
	OnlyContainsUserCerts      bool                  `asn1:"optional,tag:1"`
	OnlyContainsCACerts        bool                  `asn1:"optional,tag:2"`
	OnlySomeReasons            asn1.BitString        `asn1:"optional,tag:3"`
	IndirectCRL                bool                  `asn1:"optional,tag:4"`
	OnlyContainsAttributeCerts bool                  `asn1:"optional,tag:5"`
}

// TBSCertList represents the ASN.1 structure of the same name from RFC
// 5280, section 5.1.  It has the same content as pkix.TBSCertificateList
// but the extensions are included in a parsed format.
type TBSCertList struct {
	Raw                 asn1.RawContent
	Version             int
	Signature           pkix.AlgorithmIdentifier
	Issuer              pkix.RDNSequence
	ThisUpdate          time.Time
	NextUpdate          time.Time
	RevokedCertificates []*RevokedCertificate
	Extensions          []pkix.Extension
	// Cracked out extensions:
	AuthorityKeyID               []byte
	IssuerAltNames               GeneralNames
	CRLNumber                    int
	BaseCRLNumber                int // -1 if no delta CRL present
	IssuingDistributionPoint     IssuingDistributionPoint
	IssuingDPFullNames           GeneralNames
	FreshestCRLDistributionPoint []string
	OCSPServer                   []string
	IssuingCertificateURL        []string
}

// ParseCertificateList parses a CertificateList (e.g. a CRL) from the given
// bytes. It's often the case that PEM encoded CRLs will appear where they
// should be DER encoded, so this function will transparently handle PEM
// encoding as long as there isn't any leading garbage.
func ParseCertificateList(clBytes []byte) (*CertificateList, error) {
	if bytes.HasPrefix(clBytes, pemCRLPrefix) {
		block, _ := pem.Decode(clBytes)
		if block != nil && block.Type == pemType {
			clBytes = block.Bytes
		}
	}
	return ParseCertificateListDER(clBytes)
}

// ParseCertificateListDER parses a DER encoded CertificateList from the given bytes.
func ParseCertificateListDER(derBytes []byte) (*CertificateList, error) {
	// First parse the DER into the pkix structures.
	pkixList := new(pkix.CertificateList)
	if rest, err := asn1.Unmarshal(derBytes, pkixList); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after CRL")
	}

	// Transcribe the revoked certs but crack out extensions.
	revokedCerts := make([]*RevokedCertificate, len(pkixList.TBSCertList.RevokedCertificates))
	for i, pkixRevoked := range pkixList.TBSCertList.RevokedCertificates {
		var err error
		if revokedCerts[i], err = parseRevokedCertificate(pkixRevoked); err != nil {
			return nil, err
		}
	}

	certList := CertificateList{
		Raw: derBytes,
		TBSCertList: TBSCertList{
			Raw:                 pkixList.TBSCertList.Raw,
			Version:             pkixList.TBSCertList.Version,
			Signature:           pkixList.TBSCertList.Signature,
			Issuer:              pkixList.TBSCertList.Issuer,
			ThisUpdate:          pkixList.TBSCertList.ThisUpdate,
			NextUpdate:          pkixList.TBSCertList.NextUpdate,
			RevokedCertificates: revokedCerts,
			Extensions:          pkixList.TBSCertList.Extensions,
			CRLNumber:           -1,
			BaseCRLNumber:       -1,
		},
		SignatureAlgorithm: pkixList.SignatureAlgorithm,
		SignatureValue:     pkixList.SignatureValue,
	}

	// Now crack out extensions.
	for _, e := range certList.TBSCertList.Extensions {
		if expectCritical, present := listExtCritical[e.Id.String()]; present {
			if e.Critical && !expectCritical {
				return nil, fmt.Errorf("x509: extension %v marked critical, expect non-critical", e.Id)
			} else if !e.Critical && expectCritical {
				return nil, fmt.Errorf("x509: extension %v marked non-critical, expect critical", e.Id)
			}
		}
		switch {
		case e.Id.Equal(OIDExtensionAuthorityKeyId):
			// RFC 5280 s5.2.1
			var a authKeyId
			if rest, err := asn1.Unmarshal(e.Value, &a); err != nil {
				return nil, fmt.Errorf("x509: failed to unmarshal X.509 authority key-id: %v", err)
			} else if len(rest) != 0 {
				return nil, errors.New("x509: trailing data after X.509 authority key-id")
			}
			certList.TBSCertList.AuthorityKeyID = a.Id
		case e.Id.Equal(OIDExtensionIssuerAltName):
			// RFC 5280 s5.2.2
			if err := parseGeneralNames(e.Value, &certList.TBSCertList.IssuerAltNames); err != nil {
				return nil, fmt.Errorf("x509: failed to parse IssuerAltNames: %v", err)
			}
		case e.Id.Equal(OIDExtensionCRLNumber):
			// RFC 5280 s5.2.3
			if rest, err := asn1.Unmarshal(e.Value, &certList.TBSCertList.CRLNumber); err != nil {
				return nil, fmt.Errorf("x509: failed to unmarshal X.509 CRL number: %v", err)
			} else if len(rest) != 0 {
				return nil, errors.New("x509: trailing data after X.509 CRL number")
			}
			if certList.TBSCertList.CRLNumber < 0 {
				return nil, fmt.Errorf("x509: negative X.509 CRL number: %d", certList.TBSCertList.CRLNumber)
			}
		case e.Id.Equal(OIDExtensionDeltaCRLIndicator):
			// RFC 5280 s5.2.4
			if rest, err := asn1.Unmarshal(e.Value, &certList.TBSCertList.BaseCRLNumber); err != nil {
				return nil, fmt.Errorf("x509: failed to unmarshal X.509 base CRL number: %v", err)
			} else if len(rest) != 0 {
				return nil, errors.New("x509: trailing data after X.509 base CRL number")
			}
			if certList.TBSCertList.BaseCRLNumber < 0 {
				return nil, fmt.Errorf("x509: negative X.509 delta CRL base: %d", certList.TBSCertList.BaseCRLNumber)
			}
		case e.Id.Equal(OIDExtensionIssuingDistributionPoint):
			if err := parseIssuingDistributionPoint(e.Value, &certList.TBSCertList.IssuingDistributionPoint, &certList.TBSCertList.IssuingDPFullNames); err != nil {
				return nil, err
			}
		case e.Id.Equal(OIDExtensionFreshestCRL):
			// RFC 5280 s5.2.6
			if err := parseDistributionPoints(e.Value, &certList.TBSCertList.FreshestCRLDistributionPoint); err != nil {
				return nil, err
			}
		case e.Id.Equal(OIDExtensionAuthorityInfoAccess):
			// RFC 5280 s5.2.7
			var aia []authorityInfoAccess
			if rest, err := asn1.Unmarshal(e.Value, &aia); err != nil {
				return nil, fmt.Errorf("x509: failed to unmarshal X.509 authority information: %v", err)
			} else if len(rest) != 0 {
				return nil, errors.New("x509: trailing data after X.509 authority information")
			}

			for _, v := range aia {
				// GeneralName: uniformResourceIdentifier [6] IA5String
				if v.Location.Tag != tagURI {
					continue
				}
				switch {
				case v.Method.Equal(OIDAuthorityInfoAccessOCSP):
					certList.TBSCertList.OCSPServer = append(certList.TBSCertList.OCSPServer, string(v.Location.Bytes))
				case v.Method.Equal(OIDAuthorityInfoAccessIssuers):
					certList.TBSCertList.IssuingCertificateURL = append(certList.TBSCertList.IssuingCertificateURL, string(v.Location.Bytes))
				}
				// TODO(drysdale): cope with more possibilities
			}
		default:
			if e.Critical {
				return nil, fmt.Errorf("unhandled critical extension in revokedCertificate: %v", e.Id)
			}
		}
	}

	return &certList, nil
}

func parseIssuingDistributionPoint(data []byte, idp *IssuingDistributionPoint, name *GeneralNames) error {
	// RFC 5280 s5.2.5
	if rest, err := asn1.Unmarshal(data, idp); err != nil {
		return fmt.Errorf("x509: failed to unmarshal X.509 CRL issuing-distribution-point: %v", err)
	} else if len(rest) != 0 {
		return errors.New("x509: trailing data after X.509 CRL issuing-distribution-point")
	}

	typeCount := 0
	if idp.OnlyContainsUserCerts {
		typeCount++
	}
	if idp.OnlyContainsCACerts {
		typeCount++
	}
	if idp.OnlyContainsAttributeCerts {
		typeCount++
	}
	if typeCount > 1 {
		return fmt.Errorf("x509: multiple cert types set in issuing-distribution-point: user:%v CA:%v attr:%v",
			idp.OnlyContainsUserCerts, idp.OnlyContainsCACerts, idp.OnlyContainsAttributeCerts)
	}
	fnData := idp.DistributionPoint.FullName.FullBytes
	if len(fnData) > 0 {
		// Replace the leading context-specific tag [0] with the SEQUENCE tag.
		data := make([]byte, len(fnData))
		copy(data, fnData)
		data[0] = 0x30
		err := parseGeneralNames(data, name)
		if err != nil {
			return fmt.Errorf("x509: failed to parse X.509 CRL issuing-distribution-point fullName: %v", err)
		}
	}
	return nil
}

// RevokedCertificate represents the unnamed ASN.1 structure that makes up the
// revokedCertificates member of the TBSCertList structure from RFC 5280, s5.1.
// It has the same content as pkix.RevokedCertificate but the extensions are
// included in a parsed format.
type RevokedCertificate struct {
	pkix.RevokedCertificate
	// Cracked out extensions:
	RevocationReason RevocationReasonCode
	InvalidityDate   time.Time
	Issuer           GeneralNames
}

func parseRevokedCertificate(pkixRevoked pkix.RevokedCertificate) (*RevokedCertificate, error) {
	result := RevokedCertificate{RevokedCertificate: pkixRevoked}
	for _, e := range pkixRevoked.Extensions {
		if expectCritical, present := certExtCritical[e.Id.String()]; present {
			if e.Critical && !expectCritical {
				return nil, fmt.Errorf("x509: extension %v marked critical, expect non-critical", e.Id)
			} else if !e.Critical && expectCritical {
				return nil, fmt.Errorf("x509: extension %v marked non-critical, expect critical", e.Id)
			}
		}
		switch {
		case e.Id.Equal(OIDExtensionCRLReasons):
			// RFC 5280, s5.3.1
			var reason asn1.Enumerated
			if rest, err := asn1.Unmarshal(e.Value, &reason); err != nil {
				return nil, fmt.Errorf("x509: failed to unmarshal revocation reason: %v", err)
			} else if len(rest) != 0 {
				return nil, errors.New("x509: trailing data after revocation reason")
			}
			result.RevocationReason = RevocationReasonCode(reason)
		case e.Id.Equal(OIDExtensionInvalidityDate):
			// RFC 5280, s5.3.2
			if rest, err := asn1.Unmarshal(e.Value, &result.InvalidityDate); err != nil {
				return nil, fmt.Errorf("x509: failed to unmarshal invalidity date: %v", err)
			} else if len(rest) != 0 {
				return nil, errors.New("x509: trailing data after invalidity date")
			}
		case e.Id.Equal(OIDExtensionCertificateIssuer):
			// RFC 5280, s5.3.3
			if err := parseGeneralNames(e.Value, &result.Issuer); err != nil {
				return nil, fmt.Errorf("x509: failed to unmarshal issuer: %v", err)
			}
		default:
			if e.Critical {
				return nil, fmt.Errorf("unhandled critical extension in revokedCertificate: %v", e.Id)
			}
		}
	}
	return &result, nil
}

// CheckCertificateListSignature checks that the signature in crl is from c.
func (c *Certificate) CheckCertificateListSignature(crl *CertificateList) error {
	algo := SignatureAlgorithmFromAI(crl.SignatureAlgorithm)
	return c.CheckSignature(algo, crl.TBSCertList.Raw, crl.SignatureValue.RightAlign())
}
