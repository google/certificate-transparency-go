// Copyright 2017 Google LLC. All Rights Reserved.
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
	"io"
	"net/http"
	"os"
	"time"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"
	"k8s.io/klog/v2"
)

var (
	caFile      = flag.String("ca", "", "CA certificate file")
	strict      = flag.Bool("strict", false, "Strict validation of CRL contents")
	expectCerts = flag.Bool("cert", false, "Input files are certificates not CRLs")
)

func main() {
	klog.InitFlags(nil)
	flag.Parse()

	// Build a list of possible CA certs from command line arguments.
	var caCerts []*x509.Certificate
	if *caFile != "" {
		caDataList, err := x509util.ReadPossiblePEMFile(*caFile, "CERTIFICATE")
		if err != nil {
			klog.Exitf("%s: failed to read CA cert data: %v", *caFile, err)
		}
		for _, caData := range caDataList {
			certs, err := x509.ParseCertificates(caData)
			if err != nil {
				klog.Errorf("%s: %v", *caFile, err)
			}
			if len(certs) == 0 {
				klog.Errorf("%s: no certificates found", *caFile)
			}
			caCerts = append(caCerts, certs[0])
		}
	}

	errored := false
	for _, arg := range flag.Args() {
		if *expectCerts {
			if err := processCertArg(arg, caCerts); err != nil {
				klog.Errorf("%s: failed to read certificate data: %v", arg, err)
				errored = true
			}
		} else {
			if err := processCRLArg(arg, caCerts); err != nil {
				klog.Errorf("%s: failed to read CRL data: %v", arg, err)
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
	klog.Infof("Processing CRL:\n%s", x509util.CRLToString(certList))

	verified := false
	if len(caCerts) == 0 {
		klog.Warningf("Skipping signature validation as no CA certs available")
		verified = true
	}
	var verifyErr error
	for _, caCert := range caCerts {
		if err := caCert.CheckCertificateListSignature(certList); err != nil {
			verifyErr = err
		} else {
			klog.Infof("CRL signature verified against CA cert %q", x509util.NameToString(caCert.Subject))
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
				klog.Warningf("Failed to parse [%d] in chain: %v", i, err)
				continue
			}
			klog.Infof("Treating cert [%d] with subject %q as potential issuer", i, x509util.NameToString(issuer.Subject))
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
	issuer, err := x509util.GetIssuer(cert, client)
	if err != nil {
		klog.Warningf("Failed to retrieve issuer for cert: %v", err)
	}
	if issuer != nil {
		klog.Infof("Using issuer %q", x509util.NameToString(issuer.Subject))
		caCerts = append(caCerts, issuer)
	}
	expired := false
	if time.Now().After(cert.NotAfter) {
		klog.Errorf("Certificate is expired (since %v)", cert.NotAfter)
		expired = true
	}
	for _, crldp := range cert.CRLDistributionPoints {
		klog.Infof("Retrieving CRL from %q", crldp)
		rsp, err := client.Get(crldp)
		if err != nil || rsp.StatusCode != http.StatusOK {
			return fmt.Errorf("failed to get CRL from %q: %v", crldp, err)
		}
		body, err := io.ReadAll(rsp.Body)
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
				klog.Errorf("%s: certificate with serial number %v revoked at %v", crldp, cert.SerialNumber, rev.RevocationTime)
				if rev.RevocationReason != x509.Unspecified {
					klog.Errorf("  revocation reason: %s\v", x509util.RevocationReasonToString(rev.RevocationReason))
				}
				break
			}
		}
	}

	return nil
}
