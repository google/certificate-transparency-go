// Copyright 2019 Google Inc. All Rights Reserved.
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

package submission

import (
	"context"
	"fmt"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/loglist"
)

type rootInfo struct {
	raw      []byte
	filename string
}

// Stub for AddLogCLient interface
type stubLogClient struct {
	logURL     string
	rootsCerts map[string][]rootInfo
}

func (m stubLogClient) AddChain(ctx context.Context, chain []ct.ASN1Cert) (*ct.SignedCertificateTimestamp, error) {
	return nil, nil
}

func (m stubLogClient) AddPreChain(ctx context.Context, chain []ct.ASN1Cert) (*ct.SignedCertificateTimestamp, error) {
	if _, ok := m.rootsCerts[m.logURL]; ok {
		return testSCT(m.logURL), nil
	}
	return nil, fmt.Errorf("log %q has no roots", m.logURL)
}

func (m stubLogClient) GetAcceptedRoots(ctx context.Context) ([]ct.ASN1Cert, error) {
	roots := []ct.ASN1Cert{}
	certInfos, ok := m.rootsCerts[m.logURL]
	if !ok {
		return roots, nil
	}
	for _, certInfo := range certInfos {
		if len(certInfo.raw) > 0 {
			roots = append(roots, ct.ASN1Cert{Data: certInfo.raw})
			continue
		}
		roots = append(roots, ct.ASN1Cert{Data: readCertFile(certInfo.filename)})
	}
	return roots, nil
}

func buildRootedStubLC(log *loglist.Log, rCerts map[string][]rootInfo) (client.AddLogClient, error) {
	return stubLogClient{logURL: log.URL, rootsCerts: rCerts}, nil
}

func buildEmptyStubLogClient(log *loglist.Log) (client.AddLogClient, error) {
	return buildRootedStubLc(log, map[string][]rootInfo{})
}

func buildStubLC(log *loglist.Log) (client.AddLogClient, error) {
	return stubLogClient{logURL: log.URL, rootsCerts: map[string][]rootInfo{log.URL: {}}}, nil
}
