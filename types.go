package ct

import (
	"encoding/base64"
	"fmt"

	"github.com/google/certificate-transparency/go/x509"
)

const (
	issuerKeyHashLength = 32
)

///////////////////////////////////////////////////////////////////////////////
// The following structures represent those outlined in the RFC6962 document:
///////////////////////////////////////////////////////////////////////////////

// LogEntryType represents the LogEntryType enum from section 3.1 of the RFC:
//   enum { x509_entry(0), precert_entry(1), (65535) } LogEntryType;
type LogEntryType uint16

func (e LogEntryType) String() string {
	switch e {
	case X509LogEntryType:
		return "X509LogEntryType"
	case PrecertLogEntryType:
		return "PrecertLogEntryType"
	}
	panic(fmt.Sprintf("No string defined for LogEntryType constant value %d", e))
}

// LogEntryType constants, see section 3.1 of RFC6962.
const (
	X509LogEntryType    LogEntryType = 0
	PrecertLogEntryType LogEntryType = 1
)

// MerkleLeafType represents the MerkleLeafType enum from section 3.4 of the
// RFC: enum { timestamped_entry(0), (255) } MerkleLeafType;
type MerkleLeafType uint8

func (m MerkleLeafType) String() string {
	switch m {
	case TimestampedEntryLeafType:
		return "TimestampedEntryLeafType"
	default:
		return fmt.Sprintf("UnknownLeafType(%d)", m)
	}
}

// MerkleLeafType constants, see section 3.4 of the RFC.
const (
	TimestampedEntryLeafType MerkleLeafType = 0 // Entry type for an SCT
)

// Version represents the Version enum from section 3.2 of the RFC:
// enum { v1(0), (255) } Version;
type Version uint8

func (v Version) String() string {
	switch v {
	case V1:
		return "V1"
	default:
		return fmt.Sprintf("UnknownVersion(%d)", v)
	}
}

// CT Version constants, see section 3.2 of the RFC.
const (
	V1 Version = 0
)

// SignatureType differentiates STH signatures from SCT signatures, see RFC
// section 3.2
type SignatureType uint8

func (st SignatureType) String() string {
	switch st {
	case CertificateTimestampSignatureType:
		return "CertificateTimestamp"
	case TreeHashSignatureType:
		return "TreeHash"
	default:
		return fmt.Sprintf("UnknownSignatureType(%d)", st)
	}
}

// SignatureType constants, see RFC section 3.2
const (
	CertificateTimestampSignatureType SignatureType = 0
	TreeHashSignatureType             SignatureType = 1
)

// ASN1Cert type for holding the raw DER bytes of an ASN.1 Certificate
// (section 3.1)
type ASN1Cert []byte

// PreCert represents a Precertificate (section 3.2)
type PreCert struct {
	IssuerKeyHash  [issuerKeyHashLength]byte
	TBSCertificate []byte
}

// CTExtensions is a representation of the raw bytes of any CtExtension
// structure (see section 3.2)
type CTExtensions []byte

// MerkleTreeNode represents an internal node in the CT tree
type MerkleTreeNode []byte

// ConsistencyProof represents a CT consistency proof (see sections 2.1.2 and
// 4.4)
type ConsistencyProof []MerkleTreeNode

// AuditPath represents a CT inclusion proof (see sections 2.1.1 and 4.5)
type AuditPath []MerkleTreeNode

// LeafInput represents a serialized MerkleTreeLeaf structure
type LeafInput []byte

// LogEntry represents the contents of an entry in a CT log, see section 3.1.
type LogEntry struct {
	Index    int64
	Leaf     MerkleTreeLeaf
	X509Cert *x509.Certificate
	Precert  *Precertificate
	Chain    []ASN1Cert
}

// SignedTreeHead represents the structure returned by the get-sth CT method
// after base64 decoding. See sections 3.5 and 4.3 in the RFC)
type SignedTreeHead struct {
	TreeSize          uint64 // The number of entries in the new tree
	Timestamp         uint64 // The time at which the STH was created
	SHA256RootHash    []byte // The root hash of the log's Merkle tree
	TreeHeadSignature []byte // The Log's signature for this STH (see RFC section 3.5)
}

// SignedCertificateTimestamp represents the structure returned by the
// add-chain and add-pre-chain methods after base64 decoding. (see RFC sections
// 3.2 ,4.1 and 4.2)
type SignedCertificateTimestamp struct {
	SCTVersion Version // The version of the protocol to which the SCT conforms
	LogID      []byte  // the SHA-256 hash of the log's public key, calculated over
	// the DER encoding of the key represented as SubjectPublicKeyInfo.
	Timestamp  uint64       // Timestamp (in ms since unix epoc) at which the SCT was issued
	Extensions CTExtensions // For future extensions to the protocol
	Signature  []byte       // The Log's signature for this SCT
}

func (s SignedCertificateTimestamp) String() string {
	return fmt.Sprintf("{Version:%d LogId:%s Timestamp:%d Extensions:'%s' Signature:%s}", s.SCTVersion,
		base64.StdEncoding.EncodeToString(s.LogID),
		s.Timestamp,
		s.Extensions,
		base64.StdEncoding.EncodeToString(s.Signature))
}

// TimestampedEntry is part of the MerkleTreeLeaf structure.
// See RFC section 3.4
type TimestampedEntry struct {
	Timestamp    uint64
	EntryType    LogEntryType
	X509Entry    ASN1Cert
	PrecertEntry PreCert
	Extensions   CTExtensions
}

// MerkleTreeLeaf represents the deserialized sructure of the hash input for the
// leaves of a log's Merkle tree. See RFC section 3.4
type MerkleTreeLeaf struct {
	Version          Version          // the version of the protocol to which the MerkleTreeLeaf corresponds
	LeafType         MerkleLeafType   // The type of the leaf input, currently only TimestampedEntry can exist
	TimestampedEntry TimestampedEntry // The entry data itself
}

// Precertificate represents the parsed CT Precertificate structure.
type Precertificate struct {
	// Raw DER bytes of the precert
	Raw []byte
	// SHA256 hash of the issuing key
	IssuerKeyHash [issuerKeyHashLength]byte
	// Parsed TBSCertificate structure (held in an x509.Certificate for ease of
	// access.
	TBSCertificate x509.Certificate
}

// X509Certificate returns the X.509 Certificate contained within the
// MerkleTreeLeaf.
// Returns a pointer to an x509.Certificate or a non-nil error.
func (m *MerkleTreeLeaf) X509Certificate() (*x509.Certificate, error) {
	return x509.ParseCertificate(m.TimestampedEntry.X509Entry)
}
