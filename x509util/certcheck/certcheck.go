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

// certcheck is a utility to show and check the contents of certificates.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"

	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"
)

var (
	root                      = flag.String("root", "", "Root CA certificate file")
	intermediate              = flag.String("intermediate", "", "Intermediate CA certificate file")
	verbose                   = flag.Bool("verbose", false, "Verbose output")
	validate                  = flag.Bool("validate", false, "Validate certificate signatures")
	timecheck                 = flag.Bool("timecheck", false, "Check current validity of certificate")
	revokecheck               = flag.Bool("check_revocation", false, "Check revocation status of certificate")
	ignoreUnknownCriticalExts = flag.Bool("ignore_unknown_critical_exts", false, "Ignore unknown-critical-extension errors")
)

func addCerts(filename string, pool *x509.CertPool) {
	if filename != "" {
		dataList, err := x509util.ReadPossiblePEMFile(filename, "CERTIFICATE")
		if err != nil {
			glog.Exitf("Failed to read certificate file: %v", err)
		}
		for _, data := range dataList {
			certs, err := x509.ParseCertificates(data)
			if err != nil {
				glog.Exitf("Failed to parse certificate from %s: %v", filename, err)
			}
			for _, cert := range certs {
				pool.AddCert(cert)
			}
		}
	}
}

func main() {
	flag.Parse()

	failed := false
	for _, filename := range flag.Args() {
		dataList, err := x509util.ReadPossiblePEMFile(filename, "CERTIFICATE")
		if err != nil {
			glog.Errorf("%s: Failed to read data: %v", filename, err)
			failed = true
			continue
		}
		var chain []*x509.Certificate
		for _, data := range dataList {
			certs, err := x509.ParseCertificates(data)
			if err != nil {
				glog.Errorf("%s: Failed to parse: %v", filename, err)
				failed = true
			}
			for _, cert := range certs {
				if *verbose {
					fmt.Print(x509util.CertificateToString(cert))
				}
				if *ignoreUnknownCriticalExts {
					// We don't want failures from Verify due to unknown critical extensions,
					// so clear them out.
					cert.UnhandledCriticalExtensions = nil
				}
				if *revokecheck {
					if err := checkRevocation(cert, *verbose); err != nil {
						glog.Errorf("%s: certificate is revoked: %v", filename, err)
						failed = true
					}
				}
				chain = append(chain, cert)
			}
		}
		if *validate && len(chain) > 0 {
			if err := validateChain(chain, *timecheck, *root, *intermediate); err != nil {
				glog.Errorf("%s: verification error: %v", filename, err)
				failed = true
			}
		}
	}
	if failed {
		os.Exit(1)
	}
}

func validateChain(chain []*x509.Certificate, timecheck bool, rootsFile, intermediatesFile string) error {
	opts := x509.VerifyOptions{
		KeyUsages:         []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		Roots:             x509.NewCertPool(),
		Intermediates:     x509.NewCertPool(),
		DisableTimeChecks: !timecheck,
	}
	addCerts(rootsFile, opts.Roots)
	addCerts(intermediatesFile, opts.Intermediates)

	if rootsFile == "" && intermediatesFile == "" {
		// No explicit CA certs provided, so assume the chain is self-contained.
		count := len(chain)
		if len(chain) > 1 {
			last := chain[len(chain)-1]
			if bytes.Equal(last.RawSubject, last.RawIssuer) {
				opts.Roots.AddCert(last)
				count--
			}
		}
		for i := 1; i < count; i++ {
			opts.Intermediates.AddCert(chain[i])
		}
	}
	_, err := chain[0].Verify(opts)
	return err
}

func checkRevocation(cert *x509.Certificate, verbose bool) error {
	for _, crldp := range cert.CRLDistributionPoints {
		crlDataList, err := x509util.ReadPossiblePEMURL(crldp, "X509 CRL")
		if err != nil {
			glog.Errorf("failed to retrieve CRL from %q: %v", crldp, err)
			continue
		}
		for _, crlData := range crlDataList {
			crl, err := x509.ParseCertificateList(crlData)
			if err != nil {
				glog.Errorf("failed to parse CRL from %q: %v", crldp, err)
				continue
			}
			if verbose {
				fmt.Printf("\nRevocation data from %s:\n", crldp)
				fmt.Print(x509util.CRLToString(crl))
			}
			for _, c := range crl.TBSCertList.RevokedCertificates {
				if c.SerialNumber.Cmp(cert.SerialNumber) == 0 {
					return fmt.Errorf("certificate is revoked since %v", c.RevocationTime)
				}
			}
		}
	}
	return nil
}
