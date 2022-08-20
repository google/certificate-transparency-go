// Copyright 2022 Google LLC. All Rights Reserved.
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

package cmd

import (
	"context"
	"encoding/pem"
	"fmt"
	"os"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"
	"github.com/spf13/cobra"
	"k8s.io/klog/v2"
)

var (
	getFirst int64
	getLast  int64
	chainOut bool
	textOut  bool
)

func init() {
	cmd := cobra.Command{
		Use:     fmt.Sprintf("get-entries %s --first=idx [--last=idx]", connectionFlags),
		Aliases: []string{"getentries", "entries"},
		Short:   "Fetch a range of entries in the log",
		Args:    cobra.MaximumNArgs(0),
		Run: func(cmd *cobra.Command, _ []string) {
			runGetEntries(cmd.Context())
		},
	}
	cmd.Flags().Int64Var(&getFirst, "first", -1, "First entry to get")
	cmd.Flags().Int64Var(&getLast, "last", -1, "Last entry to get")
	cmd.Flags().BoolVar(&chainOut, "chain", false, "Display entire certificate chain")
	cmd.Flags().BoolVar(&textOut, "text", true, "Display certificates as text")
	rootCmd.AddCommand(&cmd)
}

// runGetEntries runs the get-entries command.
func runGetEntries(ctx context.Context) {
	logClient := connect(ctx)
	if getFirst == -1 {
		klog.Exit("No -first option supplied")
	}
	if getLast == -1 {
		getLast = getFirst
	}
	rsp, err := logClient.GetRawEntries(ctx, getFirst, getLast)
	if err != nil {
		exitWithDetails(err)
	}

	for i, rawEntry := range rsp.Entries {
		index := getFirst + int64(i)
		rle, err := ct.RawLogEntryFromLeaf(index, &rawEntry)
		if err != nil {
			fmt.Printf("Index=%d Failed to unmarshal leaf entry: %v", index, err)
			continue
		}
		showRawLogEntry(rle)
	}
}

func showRawLogEntry(rle *ct.RawLogEntry) {
	ts := rle.Leaf.TimestampedEntry
	when := ct.TimestampToTime(ts.Timestamp)
	fmt.Printf("Index=%d Timestamp=%d (%v) ", rle.Index, ts.Timestamp, when)

	switch ts.EntryType {
	case ct.X509LogEntryType:
		fmt.Printf("X.509 certificate:\n")
		showRawCert(*ts.X509Entry)
	case ct.PrecertLogEntryType:
		fmt.Printf("pre-certificate from issuer with keyhash %x:\n", ts.PrecertEntry.IssuerKeyHash)
		showRawCert(rle.Cert) // As-submitted: with signature and poison.
	default:
		fmt.Printf("Unhandled log entry type %d\n", ts.EntryType)
	}
	if chainOut {
		for _, c := range rle.Chain {
			showRawCert(c)
		}
	}
}

func showRawCert(cert ct.ASN1Cert) {
	if textOut {
		c, err := x509.ParseCertificate(cert.Data)
		if err != nil {
			klog.Errorf("Error parsing certificate: %q", err.Error())
		}
		if c == nil {
			return
		}
		showParsedCert(c)
	} else {
		showPEMData(cert.Data)
	}
}

func showParsedCert(cert *x509.Certificate) {
	if textOut {
		fmt.Printf("%s\n", x509util.CertificateToString(cert))
	} else {
		showPEMData(cert.Raw)
	}
}

func showPEMData(data []byte) {
	if err := pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: data}); err != nil {
		klog.Errorf("Failed to PEM encode cert: %q", err.Error())
	}
}
