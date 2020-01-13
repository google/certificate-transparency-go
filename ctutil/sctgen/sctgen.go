// Copyright 2020 Google Inc. All Rights Reserved.
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
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"io"
	"os"
	"time"

	"github.com/golang/glog"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/trillian/ctfe"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"

	// Register key handlers
	_ "github.com/google/trillian/crypto/keys/der/proto"
	"github.com/google/trillian/crypto/keys/pem"
	_ "github.com/google/trillian/crypto/keys/pem/proto"
	_ "github.com/google/trillian/crypto/keys/pkcs11/proto"
)

var (
	certChainFile     = flag.String("cert_chain", "", "File containing a certificate chain. An SCT will be generated for the first certificate.")
	logPrivateKeyFile = flag.String("log_private_key", "", "File containing a CT log private key.")
	logPrivateKeyPass = flag.String("log_private_key_password", "", "Password for the CT log private key.")
	timestampStr      = flag.String("timestamp", "", "Timestamp for the SCT, in RFC3339 format.")
	tlsOutputFile     = flag.String("tls_out", "", "Write the SCT in TLS format to this file.")
)

func main() {
	flag.Parse()

	logSigner, err := pem.ReadPrivateKeyFile(*logPrivateKeyFile, *logPrivateKeyPass)
	if err != nil {
		glog.Exitf("Error getting log private key: %v", err)
	}

	logID, err := ctfe.GetCTLogID(logSigner.Public())
	if err != nil {
		glog.Exitf("Error calculating log ID: %v", err)
	}

	timestamp, err := time.Parse(time.RFC3339, *timestampStr)
	if err != nil {
		glog.Exitf("Error parsing --timestamp: %v", err)
	}
	timestampMillis := uint64(timestamp.UnixNano() / 10e6)

	sct := ct.SignedCertificateTimestamp{
		SCTVersion: ct.V1,
		LogID:      ct.LogID{KeyID: logID},
		Timestamp:  timestampMillis,
	}

	rawCertChain, err := x509util.ReadPossiblePEMFile(*certChainFile, "CERTIFICATE")
	if err != nil {
		glog.Exitf("Error reading certificate chain: %v", err)
	}

	var certChain []*x509.Certificate
	for i, rawCert := range rawCertChain {
		cert, err := x509.ParseCertificate(rawCert)
		if err != nil {
			glog.Exitf("Error parsing certificate #%d: %v", i+1, err)
		}
		certChain = append(certChain, cert)
	}

	isPrecert, err := ctfe.IsPrecertificate(certChain[0])
	if err != nil {
		glog.Exitf("Error detecting pre-certificate: %v", err)
	}
	logEntryType := ct.X509LogEntryType
	if isPrecert {
		logEntryType = ct.PrecertLogEntryType
	}

	leaf, err := ct.MerkleTreeLeafFromChain(certChain, logEntryType, timestampMillis)
	if err != nil {
		glog.Exitf("Error generating log entry: %v", err)
	}

	signature, err := generateSignature(sct, ct.LogEntry{Leaf: *leaf}, logSigner)
	if err != nil {
		glog.Exitf("Error generating signature: %v", err)
	}
	sct.Signature = *signature

	if err := writeJSON(sct, os.Stdout); err != nil {
		glog.Errorf("Error writing SCT in JSON format: %v", err)
	}

	if *tlsOutputFile != "" {
		f, err := os.Create(*tlsOutputFile)
		if err != nil {
			glog.Exitf("Error creating TLS output file: %v", err)
		}
		if err := writeTLS(sct, f); err != nil {
			glog.Exitf("Error writing SCT in TLS format: %v", err)
		}
	}
}

func writeJSON(sct ct.SignedCertificateTimestamp, file io.Writer) error {
	resp := ct.AddChainResponse{
		SCTVersion: sct.SCTVersion,
		ID:         sct.LogID.KeyID[:],
		Timestamp:  sct.Timestamp,
		Signature:  sct.Signature.Signature,
	}

	jsonEncoder := json.NewEncoder(file)
	return jsonEncoder.Encode(resp)
}

func writeTLS(sct ct.SignedCertificateTimestamp, file io.Writer) error {
	sctTLS, err := tls.Marshal(sct)
	if err != nil {
		return err
	}

	_, err = file.Write(sctTLS)
	return err
}

func generateSignature(sct ct.SignedCertificateTimestamp, logEntry ct.LogEntry, signer crypto.Signer) (*ct.DigitallySigned, error) {
	signedData, err := ct.SerializeSCTSignatureInput(sct, logEntry)
	if err != nil {
		return nil, err
	}

	hash := sha256.Sum256(signedData)
	signature, err := signer.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}

	return &ct.DigitallySigned{
		Algorithm: tls.SignatureAndHashAlgorithm{
			Hash:      tls.SHA256,
			Signature: tls.SignatureAlgorithmFromPubKey(signer.Public()),
		},
		Signature: signature,
	}, nil
}
