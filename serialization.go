package ct

import (
	"crypto"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/google/certificate-transparency/go/tls"
)

// Variable size structure prefix-header byte lengths
const (
	CertificateLengthBytes      = 3
	PreCertificateLengthBytes   = 3
	ExtensionsLengthBytes       = 2
	CertificateChainLengthBytes = 3
	SignatureLengthBytes        = 2
	JSONLengthBytes             = 3
)

// Max lengths
const (
	MaxCertificateLength = (1 << 24) - 1
	MaxExtensionsLength  = (1 << 16) - 1
	MaxSCTInListLength   = (1 << 16) - 1
	MaxSCTListLength     = (1 << 16) - 1
)

func writeUint(w io.Writer, value uint64, numBytes int) error {
	buf := make([]uint8, numBytes)
	for i := 0; i < numBytes; i++ {
		buf[numBytes-i-1] = uint8(value & 0xff)
		value >>= 8
	}
	if value != 0 {
		return errors.New("numBytes was insufficiently large to represent value")
	}
	if _, err := w.Write(buf); err != nil {
		return err
	}
	return nil
}

func writeVarBytes(w io.Writer, value []byte, numLenBytes int) error {
	if err := writeUint(w, uint64(len(value)), numLenBytes); err != nil {
		return err
	}
	if _, err := w.Write(value); err != nil {
		return err
	}
	return nil
}

func readUint(r io.Reader, numBytes int) (uint64, error) {
	var l uint64
	for i := 0; i < numBytes; i++ {
		l <<= 8
		var t uint8
		if err := binary.Read(r, binary.BigEndian, &t); err != nil {
			return 0, err
		}
		l |= uint64(t)
	}
	return l, nil
}

// Reads a variable length array of bytes from |r|. |numLenBytes| specifies the
// number of (BigEndian) prefix-bytes which contain the length of the actual
// array data bytes that follow.
// Allocates an array to hold the contents and returns a slice view into it if
// the read was successful, or an error otherwise.
func readVarBytes(r io.Reader, numLenBytes int) ([]byte, error) {
	switch {
	case numLenBytes > 8:
		return nil, fmt.Errorf("numLenBytes too large (%d)", numLenBytes)
	case numLenBytes == 0:
		return nil, errors.New("numLenBytes should be > 0")
	}
	l, err := readUint(r, numLenBytes)
	if err != nil {
		return nil, err
	}
	data := make([]byte, l)
	if n, err := io.ReadFull(r, data); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return nil, fmt.Errorf("short read: expected %d but got %d", l, n)
		}
		return nil, err
	}
	return data, nil
}

func checkExtensionsFormat(ext CTExtensions) error {
	if len(ext) > MaxExtensionsLength {
		return errors.New("extensions too large")
	}
	return nil
}

// SerializeSCTSignatureInput serializes the passed in sct and log entry into
// the correct format for signing.
func SerializeSCTSignatureInput(sct SignedCertificateTimestamp, entry LogEntry) ([]byte, error) {
	switch sct.SCTVersion {
	case V1:
		input := CertificateTimestamp{
			SCTVersion:    sct.SCTVersion,
			SignatureType: CertificateTimestampSignatureType,
			Timestamp:     sct.Timestamp,
			EntryType:     entry.Leaf.TimestampedEntry.EntryType,
			Extensions:    sct.Extensions,
		}
		switch entry.Leaf.TimestampedEntry.EntryType {
		case X509LogEntryType:
			input.X509Entry = entry.Leaf.TimestampedEntry.X509Entry
		case PrecertLogEntryType:
			input.PrecertEntry = &PreCert{
				IssuerKeyHash:  entry.Leaf.TimestampedEntry.PrecertEntry.IssuerKeyHash,
				TBSCertificate: entry.Leaf.TimestampedEntry.PrecertEntry.TBSCertificate,
			}
		case XJSONLogEntryType:
			input.JSONEntry = entry.Leaf.TimestampedEntry.JSONEntry
		default:
			return nil, fmt.Errorf("unsupported entry type %s", entry.Leaf.TimestampedEntry.EntryType)
		}
		return tls.Marshal(input)
	default:
		return nil, fmt.Errorf("unknown SCT version %d", sct.SCTVersion)
	}
}

// SerializeSTHSignatureInput serializes the passed in STH into the correct
// format for signing.
func SerializeSTHSignatureInput(sth SignedTreeHead) ([]byte, error) {
	switch sth.Version {
	case V1:
		if len(sth.SHA256RootHash) != crypto.SHA256.Size() {
			return nil, fmt.Errorf("invalid TreeHash length, got %d expected %d", len(sth.SHA256RootHash), crypto.SHA256.Size())
		}

		input := TreeHeadSignature{
			Version:        sth.Version,
			SignatureType:  TreeHashSignatureType,
			Timestamp:      sth.Timestamp,
			TreeSize:       sth.TreeSize,
			SHA256RootHash: sth.SHA256RootHash,
		}
		return tls.Marshal(input)
	default:
		return nil, fmt.Errorf("unsupported STH version %d", sth.Version)
	}
}

// CreateX509MerkleTreeLeaf generates a MerkleTreeLeaf for an X509 cert
func CreateX509MerkleTreeLeaf(cert ASN1Cert, timestamp uint64) *MerkleTreeLeaf {
	return &MerkleTreeLeaf{
		Version:  V1,
		LeafType: TimestampedEntryLeafType,
		TimestampedEntry: &TimestampedEntry{
			Timestamp: timestamp,
			EntryType: X509LogEntryType,
			X509Entry: &cert,
		},
	}
}

// CreateJSONMerkleTreeLeaf creates the merkle tree leaf for json data.
func CreateJSONMerkleTreeLeaf(data interface{}, timestamp uint64) *MerkleTreeLeaf {
	jsonData, err := json.Marshal(AddJSONRequest{Data: data})
	if err != nil {
		return nil
	}
	// Match the JSON serialization implemented by json-c
	jsonStr := strings.Replace(string(jsonData), ":", ": ", -1)
	jsonStr = strings.Replace(jsonStr, ",", ", ", -1)
	jsonStr = strings.Replace(jsonStr, "{", "{ ", -1)
	jsonStr = strings.Replace(jsonStr, "}", " }", -1)
	jsonStr = strings.Replace(jsonStr, "/", `\/`, -1)
	// TODO: Pending google/certificate-transparency#1243, replace with
	// ObjectHash once supported by CT server.

	return &MerkleTreeLeaf{
		Version:  V1,
		LeafType: TimestampedEntryLeafType,
		TimestampedEntry: &TimestampedEntry{
			Timestamp: timestamp,
			EntryType: XJSONLogEntryType,
			JSONEntry: &JSONDataEntry{Data: []byte(jsonStr)},
		},
	}
}
