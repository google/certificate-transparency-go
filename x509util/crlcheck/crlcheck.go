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
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"
)

var (
	caFile      = flag.String("ca", "", "CA certificate file")
	verbose     = flag.Bool("verbose", false, "Verbose output")
	strict      = flag.Bool("strict", false, "Strict validation of CRL contents")
	expectCerts = flag.Bool("cert", false, "Input files are certificates not CRLs")
)

func main() {
	flag.Parse()

	// Build a list of possible CA certs from command line arguments.
	var caCerts []*x509.Certificate
	if *caFile != "" {
		caDataList, err := x509util.ReadPossiblePEMFile(*caFile, "CERTIFICATE")
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: Failed to read CA cert data: %v\n", *caFile, err)
			os.Exit(1)
		}
		for _, caData := range caDataList {
			certs, err := x509.ParseCertificates(caData)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s: %v\n", *caFile, err)
			}
			if len(certs) == 0 {
				fmt.Fprintf(os.Stderr, "%s: no certificates found\n", *caFile)
			}
			caCerts = append(caCerts, certs[0])
		}
	}

	errored := false
	for _, arg := range flag.Args() {
		if *expectCerts {
			if err := processCertArg(arg, caCerts); err != nil {
				fmt.Fprintf(os.Stderr, "%s: failed to read certificate data: %v\n", arg, err)
				errored = true
			}
		} else {
			if err := processCRLArg(arg, caCerts); err != nil {
				fmt.Fprintf(os.Stderr, "%s: failed to read CRL data: %v\n", arg, err)
				errored = true
			}
		}
	}

	if errored {
		os.Exit(1)
	}
}

func processCRLArg(arg string, caCerts []*x509.Certificate) error {
	dataList, err := x509util.ReadPossiblePEMURL(arg, "X509 CRL")
	if err != nil {
		return err
	}
	for _, data := range dataList {
		if _, err := processCRL(data, caCerts); err != nil {
			return err
		}
	}
	return nil
}

func processCRL(data []byte, caCerts []*x509.Certificate) (*x509.CertificateList, error) {
	certList, err := x509.ParseCertificateListDER(data)
	if certList == nil {
		return nil, fmt.Errorf("CRL parse error: %v", err)
	}
	if err != nil && *strict {
		return nil, fmt.Errorf("strict CRL parse error: %v", err)
	}
	if *verbose {
		fmt.Print(x509util.CRLToString(certList))
	}

	verified := (len(caCerts) == 0)
	var verifyErr error
	for _, caCert := range caCerts {
		if err := caCert.CheckCertificateListSignature(certList); err != nil {
			verifyErr = err
		} else {
			if *verbose {
				fmt.Printf("CRL signature verified against CA cert %q\n", x509util.NameToString(caCert.Subject))
			}
			verifyErr = nil
			verified = true
			break
		}
	}
	if !verified {
		return nil, fmt.Errorf("verification error: %v", verifyErr)
	}
	return certList, nil
}

func processCertArg(filename string, caCerts []*x509.Certificate) error {
	dataList, err := x509util.ReadPossiblePEMFile(filename, "CERTIFICATE")
	if err != nil {
		return err
	}
	if len(dataList) == 0 {
		return fmt.Errorf("no certs found in %s", filename)
	}

	if len(caCerts) == 0 {
		// No user-provided CA certs, so use any later entries in the file as possible issuers.
		for i := 1; i < len(dataList); i++ {
			issuer, err := x509.ParseCertificate(dataList[i])
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to parse [%d] in chain: %v", i, err)
				continue
			}
			if *verbose {
				fmt.Printf("treating cert [%d] with subject %q as potential issuer\n", i, x509util.NameToString(issuer.Subject))
			}
			caCerts = append(caCerts, issuer)
		}
	}
	return processCert(dataList[0], caCerts)
}

func processCert(data []byte, caCerts []*x509.Certificate) error {
	client := &http.Client{}

	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return fmt.Errorf("certificate parse error: %v", err)
	}
	issuer, err := getIssuer(cert, client)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to retrieve issuer for cert: %v\n", err)
	}
	if issuer != nil {
		if *verbose {
			fmt.Printf("using issuer %q\n", x509util.NameToString(issuer.Subject))
		}
		caCerts = append(caCerts, issuer)
	}
	expired := false
	if time.Now().After(cert.NotAfter) {
		fmt.Printf("certificate is expired (since %v)\n", cert.NotAfter)
		expired = true
	}
	for _, crldp := range cert.CRLDistributionPoints {
		if *verbose {
			fmt.Printf("retrieving CRL from %q\n", crldp)
		}
		rsp, err := client.Get(crldp)
		if err != nil || rsp.StatusCode != http.StatusOK {
			return fmt.Errorf("failed to get CRL from %q: %v", crldp, err)
		}
		body, err := ioutil.ReadAll(rsp.Body)
		if err != nil {
			return fmt.Errorf("failed to read CRL from %q: %v", crldp, err)
		}
		rsp.Body.Close()
		certList, err := processCRL(body, caCerts)
		if err != nil {
			return err
		}
		if expired {
			continue
		}
		// Check the CRL for the presence of the original cert.
		for _, rev := range certList.TBSCertList.RevokedCertificates {
			if rev.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				fmt.Printf("%s: certificate with serial number %v revoked at %v\n", crldp, cert.SerialNumber, rev.RevocationTime)
				if rev.RevocationReason != x509.Unspecified {
					fmt.Printf("  revocation reason: %s\v", x509util.RevocationReasonToString(rev.RevocationReason))
				}
				break
			}
		}
	}

	return nil
}

func getIssuer(cert *x509.Certificate, client *http.Client) (*x509.Certificate, error) {
	if len(cert.IssuingCertificateURL) == 0 {
		return nil, nil
	}
	issuerURL := cert.IssuingCertificateURL[0]
	if *verbose {
		fmt.Printf("retrieving issuer from %q\n", issuerURL)
	}
	rsp, err := client.Get(issuerURL)
	if err != nil || rsp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get issuer from %q: %v", issuerURL, err)
	}
	defer rsp.Body.Close()
	body, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read issuer from %q: %v", issuerURL, err)
	}
	issuers, err := x509.ParseCertificates(body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse issuer cert: %v", err)
	}
	return issuers[0], nil
}
