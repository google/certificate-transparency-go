package ct

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/certificate-transparency/go/asn1"
	"github.com/google/certificate-transparency/go/tls"
	"github.com/google/certificate-transparency/go/x509"
)

///////////////////////////////////////////////////////////////////////////////
// The following structures represent those outlined in RFC6962; any section
// numbers mentioned refer to that RFC.
///////////////////////////////////////////////////////////////////////////////

// LogEntryType represents the LogEntryType enum from section 3.1:
//   enum { x509_entry(0), precert_entry(1), (65535) } LogEntryType;
type LogEntryType tls.Enum // tls:"maxval:65535"

// LogEntryType constants from section 3.1.
const (
	X509LogEntryType    LogEntryType = 0
	PrecertLogEntryType LogEntryType = 1
	XJSONLogEntryType   LogEntryType = 0x8000 // Experimental.  Don't rely on this!
)

func (e LogEntryType) String() string {
	switch e {
	case X509LogEntryType:
		return "X509LogEntryType"
	case PrecertLogEntryType:
		return "PrecertLogEntryType"
	case XJSONLogEntryType:
		return "XJSONLogEntryType"
	default:
		return fmt.Sprintf("UnknownEntryType(%d)", e)
	}
}

// MerkleLeafType represents the MerkleLeafType enum from section 3.4:
//   enum { timestamped_entry(0), (255) } MerkleLeafType;
type MerkleLeafType tls.Enum // tls:"maxval:255"

// MerkleLeafType constants from section 3.4.
const TimestampedEntryLeafType MerkleLeafType = 0 // Entry type for an SCT

func (m MerkleLeafType) String() string {
	switch m {
	case TimestampedEntryLeafType:
		return "TimestampedEntryLeafType"
	default:
		return fmt.Sprintf("UnknownLeafType(%d)", m)
	}
}

// Version represents the Version enum from section 3.2:
//   enum { v1(0), (255) } Version;
type Version tls.Enum // tls:"maxval:255"

// CT Version constants from section 3.2.
const (
	V1 Version = 0
)

func (v Version) String() string {
	switch v {
	case V1:
		return "V1"
	default:
		return fmt.Sprintf("UnknownVersion(%d)", v)
	}
}

// SignatureType differentiates STH signatures from SCT signatures, see section 3.2.
//   enum { certificate_timestamp(0), tree_hash(1), (255) } SignatureType;
type SignatureType tls.Enum // tls:"maxval:255"

// SignatureType constants from section 3.2.
const (
	CertificateTimestampSignatureType SignatureType = 0
	TreeHashSignatureType             SignatureType = 1
)

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

// ASN1Cert holds an ASN.1 DER-encoded X.509 certificate; it represents the
// ASN.1Cert TLS type from section 3.1; the same type is also described in
// RFC6962-bis in section 5.2.  (The struct wrapper is needed so that
// Data becomes a field and can have a field tag.)
type ASN1Cert struct {
	Data []byte `tls:"minlen:1,maxlen:16777215"`
}

// LogID holds the hash of the Log's public key (section 3.2).
type LogID struct {
	KeyID [sha256.Size]byte
}

// PreCert represents a Precertificate (section 3.2).
type PreCert struct {
	IssuerKeyHash  [sha256.Size]byte
	TBSCertificate []byte `tls:"minlen:1,maxlen:16777215"` // DER-encoded TBSCertificate
}

// CTExtensions is a representation of the raw bytes of any CtExtension
// structure (see section 3.2).
type CTExtensions []byte // tls:"minlen:0,maxlen:65535"`

// MerkleTreeNode represents an internal node in the CT tree.
type MerkleTreeNode []byte

// ConsistencyProof represents a CT consistency proof (see sections 2.1.2 and
// 4.4).
type ConsistencyProof []MerkleTreeNode

// AuditPath represents a CT inclusion proof (see sections 2.1.1 and 4.5).
type AuditPath []MerkleTreeNode

// LeafInput represents a serialized MerkleTreeLeaf structure.
type LeafInput []byte

// DigitallySigned is a local alias for tls.DigitallySigned so that we can
// attach a MarshalJSON method.
type DigitallySigned tls.DigitallySigned

// FromBase64String populates the DigitallySigned structure from the base64 data passed in.
// Returns an error if the base64 data is invalid.
func (d *DigitallySigned) FromBase64String(b64 string) error {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return fmt.Errorf("failed to unbase64 DigitallySigned: %v", err)
	}
	var ds tls.DigitallySigned
	if rest, err := tls.Unmarshal(raw, &ds); err != nil {
		return fmt.Errorf("failed to unmarshal DigitallySigned: %v", err)
	} else if len(rest) > 0 {
		return fmt.Errorf("trailing data (%d bytes) after DigitallySigned", len(rest))
	}
	*d = DigitallySigned(ds)
	return nil
}

// Base64String returns the base64 representation of the DigitallySigned struct.
func (d DigitallySigned) Base64String() (string, error) {
	b, err := tls.Marshal(d)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// MarshalJSON implements the json.Marshaller interface.
func (d DigitallySigned) MarshalJSON() ([]byte, error) {
	b64, err := d.Base64String()
	if err != nil {
		return []byte{}, err
	}
	return []byte(`"` + b64 + `"`), nil
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (d *DigitallySigned) UnmarshalJSON(b []byte) error {
	var content string
	if err := json.Unmarshal(b, &content); err != nil {
		return fmt.Errorf("failed to unmarshal DigitallySigned: %v", err)
	}
	return d.FromBase64String(content)
}

// LogEntry represents the contents of an entry in a CT log.  This is described in
// section 3.1, but note that this structure does *not* match the TLS structure defined
// there (the TLS structure is never used directly in RFC6962).
type LogEntry struct {
	Index int64
	Leaf  MerkleTreeLeaf
	// Exactly one of the following three fields should be non-empty.
	X509Cert *x509.Certificate // Parsed X.509 certificate
	Precert  *Precertificate   // Extracted precertificate
	JSONData []byte

	Chain []ASN1Cert
}

// PrecertChainEntry holds an precertificate together with a validation chain
// for it; see section 3.1.
type PrecertChainEntry struct {
	PreCertificate   ASN1Cert   `tls:"minlen:1,maxlen:16777215"`
	CertificateChain []ASN1Cert `tls:"minlen:0,maxlen:16777215"`
}

// CertificateChain holds a chain of certificates, as returned as extra data
// for get-entries (section 4.6).
type CertificateChain struct {
	Entries []ASN1Cert `tls:"minlen:0,maxlen:16777215"`
}

// JSONDataEntry holds arbitrary data.
type JSONDataEntry struct {
	Data []byte `tls:"minlen:0,maxlen:1677215"`
}

// SHA256Hash represents the output from the SHA256 hash function.
type SHA256Hash [sha256.Size]byte

// FromBase64String populates the SHA256 struct with the contents of the base64 data passed in.
func (s *SHA256Hash) FromBase64String(b64 string) error {
	bs, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return fmt.Errorf("failed to unbase64 LogID: %v", err)
	}
	if len(bs) != sha256.Size {
		return fmt.Errorf("invalid SHA256 length, expected 32 but got %d", len(bs))
	}
	copy(s[:], bs)
	return nil
}

// Base64String returns the base64 representation of this SHA256Hash.
func (s SHA256Hash) Base64String() string {
	return base64.StdEncoding.EncodeToString(s[:])
}

// MarshalJSON implements the json.Marshaller interface for SHA256Hash.
func (s SHA256Hash) MarshalJSON() ([]byte, error) {
	return []byte(`"` + s.Base64String() + `"`), nil
}

// UnmarshalJSON implements the json.Unmarshaller interface.
func (s *SHA256Hash) UnmarshalJSON(b []byte) error {
	var content string
	if err := json.Unmarshal(b, &content); err != nil {
		return fmt.Errorf("failed to unmarshal SHA256Hash: %v", err)
	}
	return s.FromBase64String(content)
}

// SignedTreeHead represents the structure returned by the get-sth CT method
// after base64 decoding; see sections 3.5 and 4.3.
type SignedTreeHead struct {
	Version           Version         `json:"sth_version"`         // The version of the protocol to which the STH conforms
	TreeSize          uint64          `json:"tree_size"`           // The number of entries in the new tree
	Timestamp         uint64          `json:"timestamp"`           // The time at which the STH was created
	SHA256RootHash    SHA256Hash      `json:"sha256_root_hash"`    // The root hash of the log's Merkle tree
	TreeHeadSignature DigitallySigned `json:"tree_head_signature"` // Log's signature over a TLS-encoded TreeHeadSignature
	LogID             SHA256Hash      `json:"log_id"`              // The SHA256 hash of the log's public key
}

// TreeHeadSignature holds the data over which the signature in an STH is
// generated; see section 3.5
type TreeHeadSignature struct {
	Version        Version       `tls:"maxval:255"`
	SignatureType  SignatureType `tls:"maxval:255"` // == TreeHashSignatureType
	Timestamp      uint64
	TreeSize       uint64
	SHA256RootHash SHA256Hash
}

// SignedCertificateTimestamp represents the structure returned by the
// add-chain and add-pre-chain methods after base64 decoding; see sections
// 3.2, 4.1 and 4.2.
type SignedCertificateTimestamp struct {
	SCTVersion Version `tls:"maxval:255"`
	LogID      LogID
	Timestamp  uint64
	Extensions CTExtensions    `tls:"minlen:0,maxlen:65535"`
	Signature  DigitallySigned // Signature over TLS-encoded CertificateTimestamp
}

// CertificateTimestamp is the collection of data that the signature in an
// SCT is over; see section 3.2.
type CertificateTimestamp struct {
	SCTVersion    Version       `tls:"maxval:255"`
	SignatureType SignatureType `tls:"maxval:255"`
	Timestamp     uint64
	EntryType     LogEntryType   `tls:"maxval:65535"`
	X509Entry     *ASN1Cert      `tls:"selector:EntryType,val:0"`
	PrecertEntry  *PreCert       `tls:"selector:EntryType,val:1"`
	JSONEntry     *JSONDataEntry `tls:"selector:EntryType,val:32768"`
	Extensions    CTExtensions   `tls:"minlen:0,maxlen:65535"`
}

func (s SignedCertificateTimestamp) String() string {
	return fmt.Sprintf("{Version:%d LogId:%s Timestamp:%d Extensions:'%s' Signature:%v}", s.SCTVersion,
		base64.StdEncoding.EncodeToString(s.LogID.KeyID[:]),
		s.Timestamp,
		s.Extensions,
		s.Signature)
}

// TimestampedEntry is part of the MerkleTreeLeaf structure; see section 3.4.
type TimestampedEntry struct {
	Timestamp    uint64
	EntryType    LogEntryType   `tls:"maxval:65535"`
	X509Entry    *ASN1Cert      `tls:"selector:EntryType,val:0"`
	PrecertEntry *PreCert       `tls:"selector:EntryType,val:1"`
	JSONEntry    *JSONDataEntry `tls:"selector:EntryType,val:32768"`
	Extensions   CTExtensions   `tls:"minlen:0,maxlen:65535"`
}

// MerkleTreeLeaf represents the deserialized structure of the hash input for the
// leaves of a log's Merkle tree; see section 3.4.
type MerkleTreeLeaf struct {
	Version          Version           `tls:"maxval:255"`
	LeafType         MerkleLeafType    `tls:"maxval:255"`
	TimestampedEntry *TimestampedEntry `tls:"selector:LeafType,val:0"`
}

// Precertificate represents the parsed CT Precertificate structure.
type Precertificate struct {
	// Raw DER bytes of the precert
	Raw []byte
	// SHA256 hash of the issuing key
	IssuerKeyHash [sha256.Size]byte
	// Parsed TBSCertificate structure, held in an x509.Certificate for convenience.
	TBSCertificate x509.Certificate
}

// X509Certificate returns the X.509 Certificate contained within the
// MerkleTreeLeaf.
func (m *MerkleTreeLeaf) X509Certificate() (*x509.Certificate, error) {
	return x509.ParseCertificate(m.TimestampedEntry.X509Entry.Data)
}

// URI paths for Log requests; see section 4.
const (
	AddChainPath          = "/ct/v1/add-chain"
	AddPreChainPath       = "/ct/v1/add-pre-chain"
	GetSTHPath            = "/ct/v1/get-sth"
	GetEntriesPath        = "/ct/v1/get-entries"
	GetProofByHashPath    = "/ct/v1/get-proof-by-hash"
	GetSTHConsistencyPath = "/ct/v1/get-sth-consistency"
	GetRootsPath          = "/ct/v1/get-roots"
	GetEntryAndProofPath  = "/ct/v1/get-entry-and-proof"

	AddJSONPath = "/ct/v1/add-json" // Experimental addition
)

// AddChainRequest represents the JSON request body sent to the add-chain and
// add-pre-chain POST methods from sections 4.1 and 4.2.
type AddChainRequest struct {
	Chain [][]byte `json:"chain"`
}

// AddChainResponse represents the JSON response to the add-chain and
// add-pre-chain POST methods.
// An SCT represents a Log's promise to integrate a [pre-]certificate into the
// log within a defined period of time.
type AddChainResponse struct {
	SCTVersion Version `json:"sct_version"` // SCT structure version
	ID         []byte  `json:"id"`          // Log ID
	Timestamp  uint64  `json:"timestamp"`   // Timestamp of issuance
	Extensions string  `json:"extensions"`  // Holder for any CT extensions
	Signature  []byte  `json:"signature"`   // Log signature for this SCT
}

// AddJSONRequest represents the JSON request body sent to the add-json POST method.
// The corresponding response re-uses AddChainResponse.
// This is an experimental addition not covered by RFC6962.
type AddJSONRequest struct {
	Data interface{} `json:"data"`
}

// GetSTHResponse respresents the JSON response to the get-sth GET method from section 4.3.
type GetSTHResponse struct {
	TreeSize          uint64 `json:"tree_size"`           // Number of certs in the current tree
	Timestamp         uint64 `json:"timestamp"`           // Time that the tree was created
	SHA256RootHash    []byte `json:"sha256_root_hash"`    // Root hash of the tree
	TreeHeadSignature []byte `json:"tree_head_signature"` // Log signature for this STH
}

// GetSTHConsistencyResponse represents the JSON response to the get-sth-consistency
// GET method from section 4.4.  (The corresponding GET request has parameters 'first' and
// 'second'.)
type GetSTHConsistencyResponse struct {
	Consistency [][]byte `json:"consistency"`
}

// GetProofByHashResponse represents the JSON response to the get-proof-by-hash GET
// method from section 4.5.  (The corresponding GET request has parameters 'hash'
// and 'tree_size'.)
type GetProofByHashResponse struct {
	LeafIndex int64    `json:"leaf_index"` // The 0-based index of the end entity corresponding to the "hash" parameter.
	AuditPath [][]byte `json:"audit_path"` // An array of base64-encoded Merkle Tree nodes proving the inclusion of the chosen certificate.
}

// LeafEntry represents a leaf in the Log's Merkle tree
type LeafEntry struct {
	// LeafInput is a TLS-encoded MerkleTreeLeaf
	LeafInput []byte `json:"leaf_input"`
	// ExtraData holds (unsigned) extra data, normally the cert validation chain.
	ExtraData []byte `json:"extra_data"`
}

// GetEntriesResponse respresents the JSON response to the get-entries GET method
// from section 4.6.
type GetEntriesResponse struct {
	Entries []LeafEntry `json:"entries"` // the list of returned entries
}

// GetRootsResponse represents the JSON response to the get-roots GET method from section 4.7.
type GetRootsResponse struct {
	Certificates []string `json:"certificates"`
}

// GetEntryAndProofResponse represents the JSON response to the get-entry-and-proof
// GET method from section 4.8. (The corresponding GET request has parameters 'leaf_index'
// and 'tree_size'.)
type GetEntryAndProofResponse struct {
	LeafInput []byte   `json:"leaf_input"` // the entry itself
	ExtraData []byte   `json:"extra_data"` // any chain provided when the entry was added to the log
	AuditPath [][]byte `json:"audit_path"` // the corresponding proof
}

///////////////////////////////////////////////////////////////////////////////
// The following structures are for Certificate Transparency V2.
// This is based on draft-ietf-trans-rfc6962-bis-19.txt; below here, any
// references to a section number on its own refer to this document.
///////////////////////////////////////////////////////////////////////////////

// The first section holds TLS types needed for Certificate Transparency V2.

// X509ChainEntry holds a leaf certificate together with a chain of 0 or more
// entries that are needed to verify the leaf. Each entry in the chain
// verifies the preceding entry, and the first entry in the chain verifies the
// leaf.  This represents the X509ChainEntry TLS type from section 5.2.
// (The same type is also described in section 3.1 of RFC 6962 but is not
// directly used there.)
type X509ChainEntry struct {
	LeafCertificate  ASN1Cert   `tls:"minlen:1,maxlen:16777215"`
	CertificateChain []ASN1Cert `tls:"minlen:0,maxlen:16777215"`
}

// CMSPrecert holds the ASN.1 DER encoding of a CMS-encoded pre-certificate,
// where the CMS encoding is described in section 3.2.  This represents the
// CMSPrecert TLS type from section 5.2.
type CMSPrecert []byte // tls:"minlen:1,maxlen:16777215"

// PrecertChainEntryV2 holds a pre-certificate together with a chain of 0 or
// more entries that are needed to verify it.  Each entry in the chain
// verifies the preceding entry, and the first entry in the chain verifies the
// pre-certificate.  This represents the PrecertChainEntryV2 TLS type from
// section 5.2.
type PrecertChainEntryV2 struct {
	PreCertificate      CMSPrecert `tls:"minlen:1,maxlen:16777215"`
	PrecertificateChain []ASN1Cert `tls:"minlen:1,maxlen:16777215"`
}

// LogIDV2 identifies a particular Log, as the contents of an ASN.1 DER-encoded
// OBJECT IDENTIFIER.
//
// This OID is required to be less than 127 bytes, which means the TLS and
// ASN.1 encodings are compatible by adding a prefix byte 0x06:
//  TLS encoding:  1-byte length, plus L bytes of DER-encoded OID.
//  DER encoding:  1-byte 0x06 (universal/primitive/OBJECT IDENTIFIER), then
//                 1-byte length, plus L bytes of DER-encoded OID.
//
// This represents the LogID TLS type from section 5.3; it has the ..V2 suffix
// to distinguish it from the RFC 6962 LogID type.
type LogIDV2 []byte // tls:"minlen:2,maxlen:127"

// LogIDV2FromOID creates a LogIDV2 object from an asn1.ObjectIdentifier.
func LogIDV2FromOID(oid asn1.ObjectIdentifier) (LogIDV2, error) {
	der, err := asn1.Marshal(oid)
	if err != nil {
		return nil, err
	}
	// Unmarshal back again so we can extract the gooey centre.
	var val asn1.RawValue
	if _, err = asn1.Unmarshal(der, &val); err != nil {
		return nil, err
	}
	data := val.Bytes
	if len(data) > 127 {
		return nil, fmt.Errorf("ObjectIdentifier %v too long for LogIDV2", oid)
	}
	return data, nil
}

// OIDFromLogIDV2 returns the OID associated with a LogIDV2.
func OIDFromLogIDV2(logID LogIDV2) (asn1.ObjectIdentifier, error) {
	if len(logID) > 127 {
		return nil, fmt.Errorf("log ID too long")
	}
	der := make([]byte, len(logID)+2)
	der[0] = asn1.TagOID // and asn1.ClassUniversal
	der[1] = byte(len(logID))
	copy(der[2:], logID)
	var oid asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(der, &oid); err != nil {
		return nil, fmt.Errorf("malformed LogIDV2: %q", err.Error())
	}
	return oid, nil
}

// VersionedTransType indicates the variant content of a TransItem; it
// represents the VersionedTransType TLS enum from section 5.4.
type VersionedTransType tls.Enum // tls:"maxval:65535"

// VersionedTransType constants from section 5.4.
const (
	X509EntryV2           VersionedTransType = 1
	PrecertEntryV2        VersionedTransType = 2
	X509SCTV2             VersionedTransType = 3
	PrecertSCTV2          VersionedTransType = 4
	SignedTreeHeadV2      VersionedTransType = 5
	ConsistencyProofV2    VersionedTransType = 6
	InclusionProofV2      VersionedTransType = 7
	X509SCTWithProofV2    VersionedTransType = 8
	PrecertSCTWithProofV2 VersionedTransType = 9
)

// TransItem encapsulates various pieces of CT information; it represents the
// TransItem TLS type from section 5.4.
type TransItem struct {
	VersionedType             VersionedTransType                 `tls:"maxval:65535"`
	X509EntryV2Data           *TimestampedCertificateEntryDataV2 `tls:"selector:VersionedType,val:1"`
	PrecertEntryV2Data        *TimestampedCertificateEntryDataV2 `tls:"selector:VersionedType,val:2"`
	X509SCTV2Data             *SignedCertificateTimestampDataV2  `tls:"selector:VersionedType,val:3"`
	PrecertSCTV2Data          *SignedCertificateTimestampDataV2  `tls:"selector:VersionedType,val:4"`
	SignedTreeHeadV2Data      *SignedTreeHeadDataV2              `tls:"selector:VersionedType,val:5"`
	ConsistencyProofV2Data    *ConsistencyProofDataV2            `tls:"selector:VersionedType,val:6"`
	InclusionProofV2Data      *InclusionProofDataV2              `tls:"selector:VersionedType,val:7"`
	X509SCTWithProofV2Data    *SCTWithProofDataV2                `tls:"selector:VersionedType,val:8"`
	PrecertSCTWithProofV2Data *SCTWithProofDataV2                `tls:"selector:VersionedType,val:9"`
}

// MarshalJSON implements the json.Marshaller interface, so that fields of type TransItem
// are JSON encoded as base64(TLS-encode(contents)).
func (item TransItem) MarshalJSON() ([]byte, error) {
	data, err := tls.Marshal(item)
	if err != nil {
		return []byte{}, err
	}
	data64 := base64.StdEncoding.EncodeToString(data)
	return []byte(`"` + data64 + `"`), nil
}

// UnmarshalJSON implements the json.Unmarshaler interface, so that fields of type TransItem
// can be decoded from JSON values that hold base64(TLS-encode(contents)).
func (item *TransItem) UnmarshalJSON(b []byte) error {
	var data64 string
	if err := json.Unmarshal(b, &data64); err != nil {
		return fmt.Errorf("failed to json.Unmarshal TransItem: %v", err)
	}
	data, err := base64.StdEncoding.DecodeString(data64)
	if err != nil {
		return fmt.Errorf("failed to unbase64 TransItem: %v", err)
	}
	rest, err := tls.Unmarshal(data, item)
	if err != nil {
		return fmt.Errorf("failed to tls.Unmarshal TransItem: %v", err)
	} else if len(rest) > 0 {
		return errors.New("trailing data in TransItem")
	}
	return nil
}

// TBSCertificate holds an ASN.1 DER-encoded TBSCertificate, as defined in RFC
// 5280 section 4.1.  It represents the TBSCertificate TLS type from section
// 5.5.
type TBSCertificate []byte // tls:"minlen:1,maxlen:16777215"

// TimestampedCertificateEntryDataV2 describes a Log entry; it represents the
// TimestampedCertificateEntryDataV2 TLS type from section 5.5.
type TimestampedCertificateEntryDataV2 struct {
	Timestamp      uint64
	IssuerKeyHash  []byte         `tls:"minlen:32,maxlen:255"`
	TBSCertificate TBSCertificate `tls:"minlen:1,maxlen:16777215"`
	// Entries in the following MUST be ordered in increasing order
	// according to their SCTExtensionType values.
	SCTExtensions []SCTExtension `tls:"minlen:0,maxlen:65535"`
}

// SCTExtensionType indicates the type of extension data associated with an
// SCT; it represents the SctExtensionType enum from section 5.6.
type SCTExtensionType tls.Enum // tls:"maxval:65535"

// SCTExtension provides extended information about an SCT; it represents the
// SCTExtension TLS type from section 5.6.
type SCTExtension struct {
	SCTExtensionType SCTExtensionType `tls:"maxval:65535"`
	SCTExtensionData []byte           `tls:"minlen:0,maxlen:65535"`
}

// SignedCertificateTimestampDataV2 holds an SCT generated by the Log.  This
// represents the SignedCertificateTimestampDataV2 TLS type from section 5.6.
type SignedCertificateTimestampDataV2 struct {
	LogID     LogIDV2 `tls:"minlen:2,maxlen:127"`
	Timestamp uint64
	// Entries in the following MUST be ordered in increasing order
	// according to their SCTExtensionType values.
	SCTExtensions []SCTExtension `tls:"minlen:0,maxlen:65535"`
	// The following signature is over a TransItem that MUST have
	// VersionedType of X509EntryV2 or PrecertEntryV2.
	Signature tls.DigitallySigned
}

// NodeHash holds a hash value generated by the Log; it represents the
// NodeHash TLS type from section 5.7.  (The struct wrapper is needed so
// that Value becomes a field and can have a field tag.)
type NodeHash struct {
	Value []byte `tls:"minval:32,maxval:255"`
}

// STHExtensionType indicates the type of extension data associated with an
// STH; it represents the SthExtensionType enum from section 5.7.
type STHExtensionType tls.Enum // tls:"maxval:65535"

// STHExtension provides extended information about an STH; it represents the
// STHExtension TLS type from section 5.6.
type STHExtension struct {
	STHExtensionType STHExtensionType `tls:"maxval:65535"`
	STHExtensionData []byte           `tls:"minlen:0,maxlen:65535"`
}

// TreeHeadDataV2 holds information about a Log's Merkle tree head; it
// represents the TreeHeadDataV2 TLS type from section 5.7.
type TreeHeadDataV2 struct {
	Timestamp uint64
	TreeSize  uint64
	RootHash  NodeHash `tls:"minval:32,maxval:255"`
	// Entries in the following MUST be ordered in increasing order
	// according to their STHExtensionType values.
	STHExtensions []STHExtension `tls:"minlen:0,maxlen:65535"`
}

// SignedTreeHeadDataV2 gives signed information about a Log's Merkle tree
// head; it represents the SignedTreeHeadDataV2 TLS type from section 5.8.
type SignedTreeHeadDataV2 struct {
	LogID    LogIDV2 `tls:"minlen:2,maxlen:127"`
	TreeHead TreeHeadDataV2
	// The following signature is over the TLS encoding of the TreeHead value.
	Signature tls.DigitallySigned
}

// ConsistencyProofDataV2 holds hash values that prove the consistency of the
// Merkle tree between two tree sizes; it represents the
// ConsistencyProofDataV2 TLS type from section 5.9.
type ConsistencyProofDataV2 struct {
	LogID           LogIDV2 `tls:"minlen:2,maxlen:127"`
	TreeSize1       uint64
	TreeSize2       uint64
	ConsistencyPath []NodeHash `tls:"minlen:1,maxlen:65535"`
}

// InclusionProofDataV2 holds hash values that prove the inclusion of a given
// entry in the Log; it represents the InclusionProofDataV2 TLS structure from
// section 5.10.
type InclusionProofDataV2 struct {
	LogID         LogIDV2 `tls:"minlen:2,maxlen:127"`
	TreeSize      uint64
	LeafIndex     uint64
	InclusionPath []NodeHash `tls:"minlen:1,maxlen:65535"`
}

// SerializedTransItem holds a TLS-encoded TransItem structure; it represents
// the SerializedTransItem TLS type from section 8.2. (The struct wrapper is
// needed so that Data becomes a field and can have a field tag.)
type SerializedTransItem struct {
	Data []byte `tls:"minlen:1,maxlen:65535"`
}

// TransItemList holds multiple pieces of information from the same Log; it
// represents the TransItemList TLS type from section 8.2.
type TransItemList struct {
	TransItemList []SerializedTransItem `tls:"minlen:1,maxlen:65535"`
}

// SCTWithProofDataV2 provides combined information about an entry in the Log,
// including leaf and root information together.  This represents the
// SCTWithProofDataV2 structure from section 8.3.
type SCTWithProofDataV2 struct {
	SCT            SignedCertificateTimestampDataV2
	STH            SignedTreeHeadDataV2
	InclusionProof InclusionProofDataV2
}

// The second section holds code related to the web API for Certificate Transparency V2.

// URI paths for client messages, from section 6.
const (
	// POST methods
	AddChainPathV2    = "/ct/v2/add-chain"
	AddPreChainPathV2 = "/ct/v2/add-pre-chain"
	// GET methods
	GetSTHPathV2            = "/ct/v2/get-sth"
	GetSTHConsistencyPathV2 = "/ct/v2/get-sth-consistency"
	GetProofByHashPathV2    = "/ct/v2/get-proof-by-hash"
	GetAllByHashPathV2      = "/ct/v2/get-all-by-hash"
	GetEntriesPathV2        = "/ct/v2/get-entries"
	GetAnchorsPathV2        = "/ct/v2/get-anchors"
	// Optional GET methods
	GetEntryForSCTPathV2            = "/ct/v2/get-entry-for-sct"
	GetEntryForTBSCertificatePathV2 = "/ct/v2/get-entry-for-tbscertificate"
)

// Requests and responses are encoded as JSON objects (section 6) and so are
// represented here by structures with encoding/json field tags.

// ErrorV2Response holds a general error response (when HTTP response code is 4xx/5xx).
type ErrorV2Response struct {
	ErrorMessage string `json:"error_message"`
	ErrorCode    string `json:"error_code"` // One of validErrors
}

// AddChainV2Request is used to add a chain to a Log (section 6.1).
type AddChainV2Request struct {
	Chain []ASN1Cert `json:"chain"`
}

// AddChainV2Response is the corresponding response contents.
type AddChainV2Response struct {
	SCT TransItem `json:"sct"` // SCT.VersionedType == X509SCTV2
}

// AddPreChainV2Request is used to a pre-certificate to a Log (section 6.2).
type AddPreChainV2Request struct {
	Precertificate CMSPrecert `json:"precertificate"`
	Chain          []ASN1Cert `json:"chain"`
}

// AddPreChainV2Response is the corresponding response.
type AddPreChainV2Response struct {
	SCT TransItem `json:"sct"` // SCT.VersionedType == PrecertSCTV2
}

// GetSTHV2Response is the data retrieved for the latest Signed Tree Head (section 6.3).
type GetSTHV2Response struct {
	STH TransItem `json:"sth"` // STH.VersionedType == SignedTreeHeadV2
}

// GetSTHConsistencyV2Response holds the Merkle consistency proof between two signed tree
// heads (section 6.4).
type GetSTHConsistencyV2Response struct {
	Consistency TransItem `json:"consistency"` // Consistency.VersionedType == ConsistencyProofV2
	STH         TransItem `json:"sth"`         // STH.VersionedType == SignedTreeHeadV2
}

// GetProofByHashV2Response holds the Merkle inclusion proof for a leaf hash (section 6.5).
type GetProofByHashV2Response struct {
	Inclusion TransItem `json:"inclusion"` // Inclusion.VersionedType == InclusionProofV2
	STH       TransItem `json:"sth"`       // STH.VersionedType == SignedTreeHeadV2
}

// GetAllByHashV2Response holds a Merkle inclusion proof, STH and consistency proof for a
// leaf hash (section 6.6).
type GetAllByHashV2Response struct {
	Inclusion   TransItem `json:"inclusion"`   // Inclusion.VersionedType == InclusionProofV2
	STH         TransItem `json:"sth"`         // STH.VersionedType == SignedTreeHeadV2
	Consistency TransItem `json:"consistency"` // Consistency.VersionedType == ConsistencyProofV2
}

// LogEntryDetail holds the details of an individual log entry (section 6.7).
type LogEntryDetail struct {
	LeafInput TransItem `json:"leaf_input"` // LeafInput.VersionedType == X509EntryV2 or PrecertEntryV2
	LogEntry  []byte    `json:"log_entry"`  // Either X509ChainEntry or PrecertChainEntryV2, TLS-encoded.
	SCT       TransItem `json:"sct"`        // SCT.VersionedType == X509SCTV2 or PrecertSCTV2
}

// GetEntriesV2Response holds a collection of entries from a Log (section 6.7).
type GetEntriesV2Response struct {
	Entries []LogEntryDetail `json:"entries"`
	STH     TransItem        `json:"sth"` // STH.VersionedType == SignedTreeHeadV2
}

// GetAnchorsV2Response holds the accepted trust anchors for a Log (section 6.8).
type GetAnchorsV2Response struct {
	Certificates [][]byte `json:"certificates"`
	MaxChain     uint64   `json:"max_chain,omitempty"`
}

// GetEntryForSCTV2Response holds the entry number for an SCT (section 7.1).
type GetEntryForSCTV2Response struct {
	Entry uint64 `json:"entry"`
}

// GetEntriesForTBSCertificateV2Response holds a collection of log entries for a
// TBSCertificate (section 7.2).
type GetEntriesForTBSCertificateV2Response struct {
	Entries []uint64 `json:"entries"`
}

// ValidV2Errors holds the valid error codes for each client request.
var ValidV2Errors = map[string][]string{
	AddChainPathV2:                  []string{"not compliant", "unknown anchor", "bad chain", "bad certificate", "shutdown"},
	AddPreChainPathV2:               []string{"not compliant", "unknown anchor", "bad chain", "bad certificate", "shutdown"},
	GetSTHPathV2:                    []string{"not compliant"},
	GetSTHConsistencyPathV2:         []string{"not compliant", "first unknown", "second unknown"},
	GetProofByHashPathV2:            []string{"not compliant", "hash unknown", "tree_size unknown"},
	GetAllByHashPathV2:              []string{"not compliant", "hash unknown", "tree_size unknown"},
	GetEntriesPathV2:                []string{"not compliant"},
	GetAnchorsPathV2:                []string{"not compliant"},
	GetEntryForSCTPathV2:            []string{"not compliant", "bad signature", "not found"},
	GetEntryForTBSCertificatePathV2: []string{"not compliant", "bad hash", "not found"},
}
