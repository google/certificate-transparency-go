// Copyright 2016 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package client

import (
	"errors"
	"fmt"
	"strconv"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/x509"
	"golang.org/x/net/context"
)

// GetRawEntries exposes the /ct/v1/get-entries result with only the JSON parsing done.
func (c *LogClient) GetRawEntries(ctx context.Context, start, end int64) (*ct.GetEntriesResponse, error) {
	if end < 0 {
		return nil, errors.New("end should be >= 0")
	}
	if end < start {
		return nil, errors.New("start should be <= end")
	}

	params := map[string]string{
		"start": strconv.FormatInt(start, 10),
		"end":   strconv.FormatInt(end, 10),
	}
	if ctx == nil {
		ctx = context.TODO()
	}

	var resp ct.GetEntriesResponse
	_, err := c.GetAndParse(ctx, ct.GetEntriesPath, params, &resp)
	if err != nil {
		return nil, err
	}

	return &resp, nil
}

// GetEntries attempts to retrieve the entries in the sequence [|start|, |end|] from the CT log server. (see section 4.6.)
// Returns a slice of LeafInputs or a non-nil error.
func (c *LogClient) GetEntries(ctx context.Context, start, end int64) ([]ct.LogEntry, error) {
	resp, err := c.GetRawEntries(ctx, start, end)
	if err != nil {
		return nil, err
	}
	entries := make([]ct.LogEntry, len(resp.Entries))
	for index, entry := range resp.Entries {
		var leaf ct.MerkleTreeLeaf
		if rest, err := tls.Unmarshal(entry.LeafInput, &leaf); err != nil {
			return nil, fmt.Errorf("failed to unmarshal MerkleTreeLeaf for index %d: %v", index, err)
		} else if len(rest) > 0 {
			return nil, fmt.Errorf("trailing data (%d bytes) after MerkleTreeLeaf for index %d", len(rest), index)
		}
		entries[index].Leaf = leaf

		var chain []ct.ASN1Cert
		switch leaf.TimestampedEntry.EntryType {
		case ct.X509LogEntryType:
			var certChain ct.CertificateChain
			if rest, err := tls.Unmarshal(entry.ExtraData, &certChain); err != nil {
				return nil, fmt.Errorf("failed to unmarshal ExtraData for index %d: %v", index, err)
			} else if len(rest) > 0 {
				return nil, fmt.Errorf("trailing data (%d bytes) after CertificateChain for index %d", len(rest), index)
			}
			chain = certChain.Entries

			entries[index].X509Cert, err = leaf.X509Certificate()
			if _, ok := err.(x509.NonFatalErrors); !ok && err != nil {
				return nil, fmt.Errorf("failed to parse certificate in MerkleTreeLeaf for index %d: %v", index, err)
			}

		case ct.PrecertLogEntryType:
			var precertChain ct.PrecertChainEntry
			if rest, err := tls.Unmarshal(entry.ExtraData, &precertChain); err != nil {
				return nil, fmt.Errorf("failed to unmarshal PrecertChainEntry for index %d: %v", index, err)
			} else if len(rest) > 0 {
				return nil, fmt.Errorf("trailing data (%d bytes) after PrecertChainEntry for index %d", len(rest), index)
			}
			chain = precertChain.CertificateChain

			tbsCert, err := leaf.Precertificate()
			if _, ok := err.(x509.NonFatalErrors); !ok && err != nil {
				return nil, fmt.Errorf("failed to parse precertificate in MerkleTreeLeaf for index %d: %v", index, err)
			}
			entries[index].Precert = &ct.Precertificate{
				Submitted:      precertChain.PreCertificate,
				IssuerKeyHash:  leaf.TimestampedEntry.PrecertEntry.IssuerKeyHash,
				TBSCertificate: tbsCert,
			}

		default:
			return nil, fmt.Errorf("saw unknown entry type at index %d: %v", index, leaf.TimestampedEntry.EntryType)
		}
		entries[index].Chain = chain
		entries[index].Index = start + int64(index)
	}
	return entries, nil
}
