// Copyright 2019 Google LLC. All Rights Reserved.
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
	"bytes"
	"crypto"
	"fmt"
	"net/http"
	"sync"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/loglist3"
	"github.com/google/certificate-transparency-go/x509util"
)

const (
	// HttpClientTimeout timeout for Log list reader http client.
	httpClientTimeout = 10 * time.Second
	// chromeLogListPublicKeyPEM is the published key for verifying Chrome's v3 CT log lists.
	chromeLogListPublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAsu0BHGnQ++W2CTdyZyxv
HHRALOZPlnu/VMVgo2m+JZ8MNbAOH2cgXb8mvOj8flsX/qPMuKIaauO+PwROMjiq
fUpcFm80Kl7i97ZQyBDYKm3MkEYYpGN+skAR2OebX9G2DfDqFY8+jUpOOWtBNr3L
rmVcwx+FcFdMjGDlrZ5JRmoJ/SeGKiORkbbu9eY1Wd0uVhz/xI5bQb0OgII7hEj+
i/IPbJqOHgB8xQ5zWAJJ0DmG+FM6o7gk403v6W3S8qRYiR84c50KppGwe4YqSMkF
bLDleGQWLoaDSpEWtESisb4JiLaY4H+Kk0EyAhPSb+49JfUozYl+lf7iFN3qRq/S
IXXTh6z0S7Qa8EYDhKGCrpI03/+qprwy+my6fpWHi6aUIk4holUCmWvFxZDfixox
K0RlqbFDl2JXMBquwlQpm8u5wrsic1ksIv9z8x9zh4PJqNpCah0ciemI3YGRQqSe
/mRRXBiSn9YQBUPcaeqCYan+snGADFwHuXCd9xIAdFBolw9R9HTedHGUfVXPJDiF
4VusfX6BRR/qaadB+bqEArF/TzuDUr6FvOR4o8lUUxgLuZ/7HO+bHnaPFKYHHSm+
+z1lVDhhYuSZ8ax3T0C3FZpb7HMjZtpEorSV5ElKJEJwrhrBCMOD8L01EoSPrGlS
1w22i9uGHMn/uGQKo28u7AsCAwEAAQ==
-----END PUBLIC KEY-----`
)

// LogListData wraps info on external LogList, keeping its JSON source and time
// of download.
type LogListData struct {
	JSON         []byte
	List         *loglist3.LogList
	DownloadTime time.Time
}

// LogListRefresher is interface for Log List updates watcher.
type LogListRefresher interface {
	Refresh() (*LogListData, error)
	LastJSON() []byte
	Source() string
}

// logListRefresherImpl regularly reads Log-list and emits notifications when
// updates/errors observed. Implements LogListRefresher interface.
type logListRefresherImpl struct {
	// updateMu limits LogListRefresherImpl to a single Refresh() at a time.
	updateMu sync.RWMutex
	lastJSON []byte
	path     string
	client   *http.Client
	sigPath  string
	pubKey   crypto.PublicKey
}

// NewCustomLogListRefresher creates and inits a LogListRefresherImpl instance.
func NewCustomLogListRefresher(client *http.Client, llPath string) LogListRefresher {
	sigPath, pubKeyPEM, ok := defaultLogListSignatureConfig(llPath)
	if ok {
		llr, err := newLogListRefresher(client, llPath, sigPath, pubKeyPEM)
		if err != nil {
			panic(fmt.Sprintf("failed to initialize built-in log list verifier: %v", err))
		}
		return llr
	}
	llr, err := newLogListRefresher(client, llPath, "", "")
	if err != nil {
		panic(fmt.Sprintf("failed to initialize log list refresher: %v", err))
	}
	return llr
}

// NewLogListRefresher creates and inits a LogListRefresherImpl instance using
// default http.Client. Built-in Chrome log list URLs are verified against the
// published signature and public key.
func NewLogListRefresher(llPath string) LogListRefresher {
	return NewCustomLogListRefresher(&http.Client{Timeout: httpClientTimeout}, llPath)
}

// NewVerifiedLogListRefresher creates a refresher that verifies the log list
// signature using the provided PEM-encoded public key.
func NewVerifiedLogListRefresher(llPath, sigPath, pubKeyPEM string) (LogListRefresher, error) {
	return NewCustomVerifiedLogListRefresher(&http.Client{Timeout: httpClientTimeout}, llPath, sigPath, pubKeyPEM)
}

// NewCustomVerifiedLogListRefresher creates a refresher that verifies the log
// list signature using the provided PEM-encoded public key.
func NewCustomVerifiedLogListRefresher(client *http.Client, llPath, sigPath, pubKeyPEM string) (LogListRefresher, error) {
	return newLogListRefresher(client, llPath, sigPath, pubKeyPEM)
}

func defaultLogListSignatureConfig(llPath string) (string, string, bool) {
	switch llPath {
	case loglist3.LogListURL:
		return loglist3.LogListSignatureURL, chromeLogListPublicKeyPEM, true
	case loglist3.AllLogListURL:
		return loglist3.AllLogListSignatureURL, chromeLogListPublicKeyPEM, true
	default:
		return "", "", false
	}
}

func newLogListRefresher(client *http.Client, llPath, sigPath, pubKeyPEM string) (*logListRefresherImpl, error) {
	llr := &logListRefresherImpl{
		path:   llPath,
		client: client,
	}
	if sigPath == "" && pubKeyPEM == "" {
		return llr, nil
	}
	if sigPath == "" || pubKeyPEM == "" {
		return nil, fmt.Errorf("signature path and public key must both be provided")
	}

	pubKey, _, rest, err := ct.PublicKeyFromPEM([]byte(pubKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("failed to parse log list public key: %v", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("failed to parse log list public key: trailing data (%d bytes)", len(rest))
	}
	llr.sigPath = sigPath
	llr.pubKey = pubKey
	return llr, nil
}

// Refresh fetches the log list and returns its source, formed LogList and
// timestamp if source has changed compared to previous Refresh.
func (llr *logListRefresherImpl) Refresh() (*LogListData, error) {
	llr.updateMu.Lock()
	defer llr.updateMu.Unlock()

	t := time.Now()
	json, err := x509util.ReadFileOrURL(llr.path, llr.client)
	if err != nil {
		return nil, fmt.Errorf("failed to read %q: %v", llr.path, err)
	}

	if bytes.Equal(json, llr.lastJSON) {
		return nil, nil
	}

	var ll *loglist3.LogList
	if llr.sigPath != "" && llr.pubKey != nil {
		sig, err := x509util.ReadFileOrURL(llr.sigPath, llr.client)
		if err != nil {
			return nil, fmt.Errorf("failed to read %q signature: %v", llr.sigPath, err)
		}
		ll, err = loglist3.NewFromSignedJSON(json, sig, llr.pubKey)
		if err != nil {
			return nil, fmt.Errorf("failed to verify %q: %v", llr.path, err)
		}
	} else {
		ll, err = loglist3.NewFromJSON(json)
		if err != nil {
			return nil, fmt.Errorf("failed to parse %q: %v", llr.path, err)
		}
	}
	llr.lastJSON = json
	return &LogListData{JSON: json, List: ll, DownloadTime: t}, nil
}

// LastJSON returns last version of Log list in JSON.
func (llr *logListRefresherImpl) LastJSON() []byte {
	llr.updateMu.Lock()
	defer llr.updateMu.Unlock()
	if llr.lastJSON == nil {
		return []byte{}
	}
	return llr.lastJSON
}

// Source exposes internal Log list path.
func (llr *logListRefresherImpl) Source() string {
	return llr.path
}
