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
	"fmt"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"
	"github.com/spf13/cobra"
	"k8s.io/klog/v2"
)

var logMMD time.Duration

func init() {
	cmd := cobra.Command{
		Use:     fmt.Sprintf("upload %s --cert_chain=file [--log_mmd=dur]", connectionFlags),
		Aliases: []string{"add-chain"},
		Short:   "Submit a certificate (pre-)chain to the log",
		Args:    cobra.MaximumNArgs(0),
		Run: func(cmd *cobra.Command, _ []string) {
			runUpload(cmd.Context())
		},
	}
	// TODO(pavelkalinnikov): Don't share this parameter wiith get-inclusion-proof.
	cmd.Flags().StringVar(&certChain, "cert_chain", "", "Name of file containing certificate chain as concatenated PEM files")
	cmd.Flags().DurationVar(&logMMD, "log_mmd", 24*time.Hour, "Log's maximum merge delay")
	rootCmd.AddCommand(&cmd)
}

// runUpload runs the upload command.
func runUpload(ctx context.Context) {
	logClient := connect(ctx)
	if certChain == "" {
		klog.Exitf("No certificate chain file specified with -cert_chain")
	}
	chain, _ := chainFromFile(certChain)

	// Examine the leaf to see if it looks like a pre-certificate.
	isPrecert := false
	leaf, err := x509.ParseCertificate(chain[0].Data)
	if err == nil {
		count, _ := x509util.OIDInExtensions(x509.OIDExtensionCTPoison, leaf.Extensions)
		if count > 0 {
			isPrecert = true
			fmt.Print("Uploading pre-certificate to log\n")
		}
	}

	var sct *ct.SignedCertificateTimestamp
	if isPrecert {
		sct, err = logClient.AddPreChain(ctx, chain)
	} else {
		sct, err = logClient.AddChain(ctx, chain)
	}
	if err != nil {
		exitWithDetails(err)
	}
	// Calculate the leaf hash.
	leafEntry := ct.CreateX509MerkleTreeLeaf(chain[0], sct.Timestamp)
	leafHash, err := ct.LeafHashForLeaf(leafEntry)
	if err != nil {
		klog.Exitf("Failed to create hash of leaf: %v", err)
	}

	// Display the SCT.
	when := ct.TimestampToTime(sct.Timestamp)
	fmt.Printf("Uploaded chain of %d certs to %v log at %v, timestamp: %d (%v)\n", len(chain), sct.SCTVersion, logClient.BaseURI(), sct.Timestamp, when)
	fmt.Printf("LogID: %x\n", sct.LogID.KeyID[:])
	fmt.Printf("LeafHash: %x\n", leafHash)
	fmt.Printf("Signature: %v\n", signatureToString(&sct.Signature))

	age := time.Since(when)
	if age > logMMD {
		// SCT's timestamp is old enough that the certificate should be included.
		getInclusionProofForHash(ctx, logClient, leafHash[:])
	}
}
