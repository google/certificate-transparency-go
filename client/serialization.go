package client

import (
	"bytes"
	"container/list"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Variable size structure prefix-header byte lengths
const (
	CertificateLengthBytes      = 3
	PreCertificateLengthBytes   = 3
	ExtensionsLengthBytes       = 2
	CertificateChainLengthBytes = 3
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

// Reads a list of ASN1Cert types from |r|
func readASN1CertList(r io.Reader, total_len_bytes int, element_len_bytes int) ([]ASN1Cert, error) {
	list_bytes, err := readVarBytes(r, total_len_bytes)
	if err != nil {
		return []ASN1Cert{}, err
	}
	list := list.New()
	list_reader := bytes.NewReader(list_bytes)
	var entry []byte
	for err == nil {
		entry, err = readVarBytes(list_reader, element_len_bytes)
		if err != nil {
			if err != io.EOF {
				return []ASN1Cert{}, err
			}
		} else {
			list.PushBack(entry)
		}
	}
	ret := make([]ASN1Cert, list.Len())
	i := 0
	for e := list.Front(); e != nil; e = e.Next() {
		ret[i] = e.Value.([]byte)
		i++
	}
	return ret, nil
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

// Unmarshalls the contents of the "chain:" entry in a GetEntries response in
// the case where the entry refers to an X509 leaf.
func UnmarshalX509ChainArray(b []byte) ([]ASN1Cert, error) {
	return readASN1CertList(bytes.NewReader(b), CertificateChainLengthBytes, CertificateLengthBytes)
}

// Unmarshalls the contents of the "chain:" entry in a GetEntries response in
// the case where the entry refers to a Precertificate leaf.
func UnmarshalPrecertChainArray(b []byte) ([]ASN1Cert, error) {
	var chain []ASN1Cert

	reader := bytes.NewReader(b)
	// read (and discard) the pre-cert entry:
	_, err := readVarBytes(reader, CertificateLengthBytes)
	if err != nil {
		return chain, err
	}
	// and then read and return the chain up to the root:
	return readASN1CertList(reader, CertificateChainLengthBytes, CertificateLengthBytes)
}
