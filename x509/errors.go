package x509

import "fmt"

// To preserve error IDs, only append to this list, never insert.
const (
	ErrInvalidID ErrorID = iota
	ErrInvalidCertList
	ErrTrailingCertList
	ErrUnexpectedlyCriticalCertListExtension
	ErrUnexpectedlyNonCriticalCertListExtension
	ErrInvalidCertListAuthKeyID
	ErrTrailingCertListAuthKeyID
	ErrInvalidCertListIssuerAltName
	ErrInvalidCertListCRLNumber
	ErrTrailingCertListCRLNumber
	ErrNegativeCertListCRLNumber
	ErrInvalidCertListDeltaCRL
	ErrTrailingCertListDeltaCRL
	ErrNegativeCertListDeltaCRL
	ErrInvalidCertListIssuingDP
	ErrTrailingCertListIssuingDP
	ErrCertListIssuingDPMultipleTypes
	ErrCertListIssuingDPInvalidFullName
	ErrInvalidCertListFreshestCRL
	ErrInvalidCertListAuthInfoAccess
	ErrTrailingCertListAuthInfoAccess
	ErrUnhandledCriticalCertListExtension
	ErrUnexpectedlyCriticalRevokedCertExtension
	ErrUnexpectedlyNonCriticalRevokedCertExtension
	ErrInvalidRevocationReason
	ErrTrailingRevocationReason
	ErrInvalidRevocationInvalidityDate
	ErrTrailingRevocationInvalidityDate
	ErrInvalidRevocationIssuer
	ErrUnhandledCriticalRevokedCertExtension

	ErrMaxID
)

// idToError gives a template x509.Error for each defined ErrorID; where the Summary
// field may hold format specifiers that take field parameters.
var idToError = map[ErrorID]Error{

	ErrInvalidCertList: Error{
		ID:       ErrInvalidCertList,
		Summary:  "x509: failed to parse CertificateList: %v",
		Field:    "CertificateList",
		SpecRef:  "RFC 5280 s5.1",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	ErrTrailingCertList: Error{
		ID:       ErrTrailingCertList,
		Summary:  "x509: trailing data after CertificateList",
		Field:    "CertificateList",
		SpecRef:  "RFC 5280 s5.1",
		Category: InvalidASN1Content,
		Fatal:    true,
	},

	ErrUnexpectedlyCriticalCertListExtension: Error{
		ID:       ErrUnexpectedlyCriticalCertListExtension,
		Summary:  "x509: certificate list extension %v marked critical but expected to be non-critical",
		Field:    "tbsCertList.crlExtensions.*.critical",
		SpecRef:  "RFC 5280 s5.2",
		Category: MalformedCRL,
	},
	ErrUnexpectedlyNonCriticalCertListExtension: Error{
		ID:       ErrUnexpectedlyNonCriticalCertListExtension,
		Summary:  "x509: certificate list extension %v marked non-critical but expected to be critical",
		Field:    "tbsCertList.crlExtensions.*.critical",
		SpecRef:  "RFC 5280 s5.2",
		Category: MalformedCRL,
	},

	ErrInvalidCertListAuthKeyID: Error{
		ID:       ErrInvalidCertListAuthKeyID,
		Summary:  "x509: failed to unmarshal certificate-list authority key-id: %v",
		Field:    "tbsCertList.crlExtensions.*.AuthorityKeyIdentifier",
		SpecRef:  "RFC 5280 s5.2.1",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	ErrTrailingCertListAuthKeyID: Error{
		ID:       ErrTrailingCertListAuthKeyID,
		Summary:  "x509: trailing data after certificate list auth key ID",
		Field:    "tbsCertList.crlExtensions.*.AuthorityKeyIdentifier",
		SpecRef:  "RFC 5280 s5.2.1",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	ErrInvalidCertListIssuerAltName: Error{
		ID:       ErrInvalidCertListIssuerAltName,
		Summary:  "x509: failed to parse CRL issuer alt name: %v",
		Field:    "tbsCertList.crlExtensions.*.IssuerAltName",
		SpecRef:  "RFC 5280 s5.2.2",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	ErrInvalidCertListCRLNumber: Error{
		ID:       ErrInvalidCertListCRLNumber,
		Summary:  "x509: failed to unmarshal certificate-list crl-number: %v",
		Field:    "tbsCertList.crlExtensions.*.CRLNumber",
		SpecRef:  "RFC 5280 s5.2.3",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	ErrTrailingCertListCRLNumber: Error{
		ID:       ErrTrailingCertListCRLNumber,
		Summary:  "x509: trailing data after certificate list crl-number",
		Field:    "tbsCertList.crlExtensions.*.CRLNumber",
		SpecRef:  "RFC 5280 s5.2.3",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	ErrNegativeCertListCRLNumber: Error{
		ID:       ErrNegativeCertListCRLNumber,
		Summary:  "x509: negative certificate list crl-number: %d",
		Field:    "tbsCertList.crlExtensions.*.CRLNumber",
		SpecRef:  "RFC 5280 s5.2.3",
		Category: MalformedCRL,
		Fatal:    true,
	},
	ErrInvalidCertListDeltaCRL: Error{
		ID:       ErrInvalidCertListDeltaCRL,
		Summary:  "x509: failed to unmarshal certificate-list delta-crl: %v",
		Field:    "tbsCertList.crlExtensions.*.BaseCRLNumber",
		SpecRef:  "RFC 5280 s5.2.4",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	ErrTrailingCertListDeltaCRL: Error{
		ID:       ErrTrailingCertListDeltaCRL,
		Summary:  "x509: trailing data after certificate list delta-crl",
		Field:    "tbsCertList.crlExtensions.*.BaseCRLNumber",
		SpecRef:  "RFC 5280 s5.2.4",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	ErrNegativeCertListDeltaCRL: Error{
		ID:       ErrNegativeCertListDeltaCRL,
		Summary:  "x509: negative certificate list base-crl-number: %d",
		Field:    "tbsCertList.crlExtensions.*.BaseCRLNumber",
		SpecRef:  "RFC 5280 s5.2.4",
		Category: MalformedCRL,
		Fatal:    true,
	},
	ErrInvalidCertListIssuingDP: Error{
		ID:       ErrInvalidCertListIssuingDP,
		Summary:  "x509: failed to unmarshal certificate list issuing distribution point: %v",
		Field:    "tbsCertList.crlExtensions.*.IssuingDistributionPoint",
		SpecRef:  "RFC 5280 s5.2.5",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	ErrTrailingCertListIssuingDP: Error{
		ID:       ErrTrailingCertListIssuingDP,
		Summary:  "x509: trailing data after certificate list issuing distribution point",
		Field:    "tbsCertList.crlExtensions.*.IssuingDistributionPoint",
		SpecRef:  "RFC 5280 s5.2.5",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	ErrCertListIssuingDPMultipleTypes: Error{
		ID:       ErrCertListIssuingDPMultipleTypes,
		Summary:  "x509: multiple cert types set in issuing-distribution-point: user:%v CA:%v attr:%v",
		Field:    "tbsCertList.crlExtensions.*.IssuingDistributionPoint",
		SpecRef:  "RFC 5280 s5.2.5",
		SpecText: "at most one of onlyContainsUserCerts, onlyContainsCACerts, and onlyContainsAttributeCerts may be set to TRUE.",
		Category: MalformedCRL,
		Fatal:    true,
	},
	ErrCertListIssuingDPInvalidFullName: Error{
		ID:       ErrCertListIssuingDPInvalidFullName,
		Summary:  "x509: failed to parse CRL issuing-distribution-point fullName: %v",
		Field:    "tbsCertList.crlExtensions.*.IssuingDistributionPoint.distributionPoint",
		SpecRef:  "RFC 5280 s5.2.5",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	ErrInvalidCertListFreshestCRL: Error{
		ID:       ErrInvalidCertListFreshestCRL,
		Summary:  "x509: failed to unmarshal certificate list freshestCRL: %v",
		Field:    "tbsCertList.crlExtensions.*.FreshestCRL",
		SpecRef:  "RFC 5280 s5.2.6",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	ErrInvalidCertListAuthInfoAccess: Error{
		ID:       ErrInvalidCertListAuthInfoAccess,
		Summary:  "x509: failed to unmarshal certificate list authority info access: %v",
		Field:    "tbsCertList.crlExtensions.*.AuthorityInfoAccess",
		SpecRef:  "RFC 5280 s5.2.7",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	ErrTrailingCertListAuthInfoAccess: Error{
		ID:       ErrTrailingCertListAuthInfoAccess,
		Summary:  "x509: trailing data after certificate list authority info access",
		Field:    "tbsCertList.crlExtensions.*.AuthorityInfoAccess",
		SpecRef:  "RFC 5280 s5.2.7",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	ErrUnhandledCriticalCertListExtension: Error{
		ID:       ErrUnhandledCriticalCertListExtension,
		Summary:  "x509: unhandled critical extension in certificate list: %v",
		Field:    "tbsCertList.revokedCertificates.crlExtensions.*",
		SpecRef:  "RFC 5280 s5.2",
		SpecText: "If a CRL contains a critical extension that the application cannot process, then the application MUST NOT use that CRL to determine the status of certificates.",
		Category: MalformedCRL,
		Fatal:    true,
	},

	ErrUnexpectedlyCriticalRevokedCertExtension: Error{
		ID:       ErrUnexpectedlyCriticalRevokedCertExtension,
		Summary:  "x509: revoked certificate extension %v marked critical but expected to be non-critical",
		Field:    "tbsCertList.revokedCertificates.crlEntryExtensions.*.critical",
		SpecRef:  "RFC 5280 s5.3",
		Category: MalformedCRL,
	},
	ErrUnexpectedlyNonCriticalRevokedCertExtension: Error{
		ID:       ErrUnexpectedlyNonCriticalRevokedCertExtension,
		Summary:  "x509: revoked certificate extension %v marked non-critical but expected to be critical",
		Field:    "tbsCertList.revokedCertificates.crlEntryExtensions.*.critical",
		SpecRef:  "RFC 5280 s5.3",
		Category: MalformedCRL,
	},

	ErrInvalidRevocationReason: Error{
		ID:       ErrInvalidRevocationReason,
		Summary:  "x509: failed to parse revocation reason: %v",
		Field:    "tbsCertList.revokedCertificates.crlEntryExtensions.*.CRLReason",
		SpecRef:  "RFC 5280 s5.3.1",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	ErrTrailingRevocationReason: Error{
		ID:       ErrTrailingRevocationReason,
		Summary:  "x509: trailing data after revoked certificate reason",
		Field:    "tbsCertList.revokedCertificates.crlEntryExtensions.*.CRLReason",
		SpecRef:  "RFC 5280 s5.3.1",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	ErrInvalidRevocationInvalidityDate: Error{
		ID:       ErrInvalidRevocationInvalidityDate,
		Summary:  "x509: failed to parse revoked certificate invalidity date: %v",
		Field:    "tbsCertList.revokedCertificates.crlEntryExtensions.*.InvalidityDate",
		SpecRef:  "RFC 5280 s5.3.2",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	ErrTrailingRevocationInvalidityDate: Error{
		ID:       ErrTrailingRevocationInvalidityDate,
		Summary:  "x509: trailing data after revoked certificate invalidity date",
		Field:    "tbsCertList.revokedCertificates.crlEntryExtensions.*.InvalidityDate",
		SpecRef:  "RFC 5280 s5.3.2",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	ErrInvalidRevocationIssuer: Error{
		ID:       ErrInvalidRevocationIssuer,
		Summary:  "x509: failed to parse revocation issuer %v",
		Field:    "tbsCertList.revokedCertificates.crlEntryExtensions.*.CertificateIssuer",
		SpecRef:  "RFC 5280 s5.3.3",
		Category: InvalidASN1Content,
		Fatal:    true,
	},
	ErrUnhandledCriticalRevokedCertExtension: Error{
		ID:       ErrUnhandledCriticalRevokedCertExtension,
		Summary:  "x509: unhandled critical extension in revoked certificate: %v",
		Field:    "tbsCertList.revokedCertificates.crlEntryExtensions.*",
		SpecRef:  "RFC 5280 s5.3",
		SpecText: "If a CRL contains a critical CRL entry extension that the application cannot process, then the application MUST NOT use that CRL to determine the status of any certificates.",
		Category: MalformedCRL,
		Fatal:    true,
	},
}

// NewError builds a new x509.Error based on the template for the given id.
func NewError(id ErrorID, args ...interface{}) Error {
	var err Error
	if id >= ErrMaxID {
		err.ID = id
		err.Summary = fmt.Sprintf("Unknown error ID %v: args %+v", id, args)
		err.Fatal = true
	} else {
		err = idToError[id]
		err.Summary = fmt.Sprintf(err.Summary, args...)
	}
	return err
}
