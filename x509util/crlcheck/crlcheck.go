// Copyright 2017 Google Inc. All Rights Reserved.
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

// crlcheck is a utility to show and check the contents of certificate
// revocation lists (CRLs).
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"
)

var caFile = flag.String("ca", "", "CA certificate file")
var verbose = flag.Bool("verbose", false, "Verbose output")

func main() {
	flag.Parse()
	var caCert *x509.Certificate
	if *caFile != "" {
		caData, err := x509util.ReadPossiblePEMFile(*caFile, "CERTIFICATE")
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: Failed to read CA cert data: %v\n", *caFile, err)
		}
		caCerts, err := x509.ParseCertificates(caData)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", *caFile, err)
		}
		if len(caCerts) == 0 {
			fmt.Fprintf(os.Stderr, "%s: no certificates found\n", *caFile)
		}
		caCert = caCerts[0]
	}

	errcount := 0
	for _, filename := range flag.Args() {
		data, err := x509util.ReadPossiblePEMURL(filename, "X509 CRL")
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: failed to read data: %v\n", filename, err)
			errcount++
			continue
		}
		certList, err := x509.ParseCertificateListDER(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", filename, err)
			errcount++
			continue
		}
		if *verbose {
			fmt.Print(x509util.CRLToString(certList))
		}

		if caCert != nil {
			if err := caCert.CheckCertificateListSignature(certList); err != nil {
				fmt.Fprintf(os.Stderr, "%s: Verification error: %v\n", filename, err)
				errcount++
			}
		}
	}
	if errcount > 0 {
		os.Exit(1)
	}
}
