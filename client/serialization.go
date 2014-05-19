package client

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Variable size structure prefix-header byte lengths
const (
	CertificateLengthBytes    = 3
	PreCertificateLengthBytes = 3
	ExtensionsLengthBytes     = 2
)

// Reads a variable length array of bytes from |r|. |numLenBytes| specifies the
// number of (BigEndian) prefix-bytes which contain the length of the actual
// array data bytes that follow.
// Allocates an array to hold the contents and returns a slice view into it if
// the read was successful, or an error otherwise.
func readVarBytes(r io.Reader, numLenBytes int) ([]byte, error) {
	var l uint64
	switch {
	case numLenBytes > 8:
		return nil, fmt.Errorf("numLenBytes too large (%d)", numLenBytes)
	case numLenBytes == 0:
		return nil, errors.New("numLenBytes should be > 0")
	}
	// Read the length header bytes
	for i := 0; i < numLenBytes; i++ {
		l <<= 8
		var t uint8
		if err := binary.Read(r, binary.BigEndian, &t); err != nil {
			return nil, err
		}
		l |= uint64(t)
	}
	data := make([]byte, l)
	n, err := r.Read(data)
	if err != nil {
		return nil, err
	}
	if n != int(l) {
		return nil, fmt.Errorf("short read: expected %d but got %d", l, n)
	}
	return data, nil
}

// Parses the byte-stream representation of a TimestampedEntry from |r| and populates
// the struct |t| with the data.
// See RFC section 3.4 for details on the format.
// Returns a non-nil error if there was a problem.
func ReadTimestampedEntryInto(r io.Reader, t *TimestampedEntry) error {
	var err error
	if err = binary.Read(r, binary.BigEndian, &t.Timestamp); err != nil {
		return err
	}
	if err = binary.Read(r, binary.BigEndian, &t.EntryType); err != nil {
		return err
	}
	switch t.EntryType {
	case X509LogEntryType:
		if t.X509Entry, err = readVarBytes(r, CertificateLengthBytes); err != nil {
			return err
		}
	case PrecertLogEntryType:
		if err := binary.Read(r, binary.BigEndian, &t.PrecertEntry.IssuerKeyHash); err != nil {
			return err
		}
		if t.PrecertEntry.TBSCertificate, err = readVarBytes(r, PreCertificateLengthBytes); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown EntryType: %d", t.EntryType)
	}
	t.Extensions, err = readVarBytes(r, ExtensionsLengthBytes)
	return nil
}

// Parses the byte-stream representation of a MerkleTreeLeaf and returns a
// pointer to a new MerkleTreeLeaf structure containing the parsed data.
// See RFC section 3.4 for details on the format.
// Returns a pointer to a new MerkleTreeLeaf or non-nil error if there was a problem
func ReadMerkleTreeLeaf(r io.Reader) (*MerkleTreeLeaf, error) {
	var m MerkleTreeLeaf
	if err := binary.Read(r, binary.BigEndian, &m.Version); err != nil {
		return nil, err
	}
	if m.Version != V1 {
		return nil, fmt.Errorf("unknown Version %d", m.Version)
	}
	if err := binary.Read(r, binary.BigEndian, &m.LeafType); err != nil {
		return nil, err
	}
	if m.LeafType != TimestampedEntryLeafType {
		return nil, fmt.Errorf("unknown LeafType %d", m.LeafType)
	}
	if err := ReadTimestampedEntryInto(r, &m.TimestampedEntry); err != nil {
		return nil, err
	}
	return &m, nil
}
