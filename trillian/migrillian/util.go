// Copyright 2018 Google Inc. All Rights Reserved.
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

package main

import (
	"crypto/sha256"
	"fmt"

	"github.com/golang/glog"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/trillian"
)

func toLogEntry(index int64, entry *ct.LeafEntry) (*ct.LogEntry, error) {
	logEntry, err := ct.LogEntryFromLeaf(index, entry)
	if _, ok := err.(x509.NonFatalErrors); !ok && err != nil {
		return nil, fmt.Errorf("failed to parse [pre-]certificate: %v", err)
	}
	return logEntry, nil
}

func buildLogLeaf(entry *ct.LogEntry) (*trillian.LogLeaf, error) {
	leafData, err := tls.Marshal(entry.Leaf)
	if err != nil {
		glog.Warningf("Failed to serialize Merkle leaf: %v", err)
		return nil, err
	}

	var raw []byte
	var extra interface{}

	if entry.Precert != nil {
		raw = entry.Precert.TBSCertificate.Raw
		// For a precert, the extra data is a TLS-encoded PrecertChainEntry.
		extra = ct.PrecertChainEntry{
			PreCertificate:   entry.Precert.Submitted,
			CertificateChain: entry.Chain,
		}
	} else {
		raw = entry.X509Cert.Raw
		// For a certificate, the extra data is a TLS-encoded:
		//   ASN.1Cert certificate_chain<0..2^24-1>;
		// containing the chain after the leaf.
		extra = ct.CertificateChain{
			Entries: entry.Chain,
		}
	}

	extraData, err := tls.Marshal(extra)
	if err != nil {
		glog.Warningf("Failed to serialize chain for ExtraData: %v", err)
		return nil, err
	}

	// leafIDHash allows Trillian to detect duplicate entries, so this should be
	// a hash over the cert data.
	leafIDHash := sha256.Sum256(raw)

	return &trillian.LogLeaf{
		LeafValue:        leafData,
		ExtraData:        extraData,
		LeafIndex:        entry.Index,
		LeafIdentityHash: leafIDHash[:],
	}, nil
}
