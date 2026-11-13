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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/certificate-transparency-go/loglist3"
	"github.com/google/certificate-transparency-go/schedule"
	cttls "github.com/google/certificate-transparency-go/tls"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/google/go-cmp/cmp"
)

// createTempFile creates a file in the system's temp directory and writes data to it.
// It returns the name of the file.
func createTempFile(data string) (string, error) {
	f, err := os.CreateTemp("", "")
	if err != nil {
		return "", err
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Fatalf("Operation to close file failed: %v", err)
		}
	}()
	if _, err := f.WriteString(data); err != nil {
		return "", err
	}
	return f.Name(), nil
}

func createTempBytesFile(data []byte) (string, error) {
	f, err := os.CreateTemp("", "")
	if err != nil {
		return "", err
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Fatalf("Operation to close file failed: %v", err)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return "", err
	}
	return f.Name(), nil
}

func createSignedLogListFiles(t *testing.T, ll string) (string, string, string) {
	t.Helper()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() = %v, want nil", err)
	}
	sig, err := cttls.CreateSignature(*privKey, cttls.SHA256, []byte(ll))
	if err != nil {
		t.Fatalf("tls.CreateSignature() = %v, want nil", err)
	}
	pubDER, err := ctx509.MarshalPKIXPublicKey(privKey.Public())
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey() = %v, want nil", err)
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	llPath, err := createTempFile(ll)
	if err != nil {
		t.Fatalf("createTempFile() = %v, want nil", err)
	}
	sigPath, err := createTempBytesFile(sig.Signature)
	if err != nil {
		if rmErr := os.Remove(llPath); rmErr != nil {
			t.Fatalf("createTempBytesFile() = %v; cleanup err = %v", err, rmErr)
		}
		t.Fatalf("createTempBytesFile() = %v, want nil", err)
	}
	return llPath, sigPath, string(pubKeyPEM)
}

func ExampleLogListRefresher() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	f, err := createTempFile(`{"operators": [{"name":"Google"}]}`)
	if err != nil {
		panic(err)
	}
	defer func() {
		if err := os.Remove(f); err != nil {
			log.Fatalf("Operation to remove temp file failed: %v", err)
		}
	}()

	llr := NewLogListRefresher(f)

	// Refresh log list periodically so it stays up-to-date.
	// Not necessary for this example, but appropriate for long-running systems.
	llChan := make(chan *LogListData)
	errChan := make(chan error)
	go schedule.Every(ctx, time.Hour, func(ctx context.Context) {
		if ll, err := llr.Refresh(); err != nil {
			errChan <- err
		} else {
			llChan <- ll
		}
	})

	select {
	case ll := <-llChan:
		fmt.Printf("# Log Operators: %d\n", len(ll.List.Operators))
	case err := <-errChan:
		panic(err)
	case <-ctx.Done():
		panic("Context expired")
	}
	// Output:
	// # Log Operators: 1
}

func TestNewLogListRefresherNoFile(t *testing.T) {
	const wantErrSubstr = "failed to read"
	llr := NewLogListRefresher("nofile.json")
	if _, err := llr.Refresh(); !strings.Contains(err.Error(), wantErrSubstr) {
		t.Errorf("llr.Refresh() = (_, %v), want err containing %q", err, wantErrSubstr)
	}
}

type fakeTransport struct {
	called bool
}

func (ft *fakeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ft.called = true
	return nil, fmt.Errorf("fakeTransport got called")
}

func TestNewCustomLogListRefresher(t *testing.T) {
	transport := fakeTransport{}
	client := &http.Client{Transport: &transport, Timeout: time.Second}

	llr := NewCustomLogListRefresher(client, "https://loglist.net/")
	if _, err := llr.Refresh(); err == nil {
		t.Errorf("Expected llr.Refresh() to return error using fakeTransport, got none")
	}
	if transport.called != true {
		t.Errorf("NewCustomLogListRefresher initialized with fakeTransport didn't call it on Refresh()")
	}
}

func TestNewLogListRefresherBuiltInURLVerifiesSignature(t *testing.T) {
	llr := NewLogListRefresher(loglist3.LogListURL)
	got, ok := llr.(*logListRefresherImpl)
	if !ok {
		t.Fatalf("NewLogListRefresher(%q) returned %T, want *logListRefresherImpl", loglist3.LogListURL, llr)
	}
	if diff := cmp.Diff(loglist3.LogListSignatureURL, got.sigPath); diff != "" {
		t.Fatalf("NewLogListRefresher(%q) sigPath diff (-want +got):\n%s", loglist3.LogListURL, diff)
	}
	if got.pubKey == nil {
		t.Fatalf("NewLogListRefresher(%q) pubKey = nil, want non-nil", loglist3.LogListURL)
	}
}

func TestNewVerifiedLogListRefresher(t *testing.T) {
	ll := `{"operators": [{"id":0,"name":"Google"}]}`
	llPath, sigPath, pubKeyPEM := createSignedLogListFiles(t, ll)
	defer func() {
		if err := os.Remove(llPath); err != nil {
			t.Fatalf("Operation to remove temp file failed: %v", err)
		}
		if err := os.Remove(sigPath); err != nil {
			t.Fatalf("Operation to remove temp file failed: %v", err)
		}
	}()

	llr, err := NewVerifiedLogListRefresher(llPath, sigPath, pubKeyPEM)
	if err != nil {
		t.Fatalf("NewVerifiedLogListRefresher() = (_, %v), want (_, nil)", err)
	}
	got, err := llr.Refresh()
	if err != nil {
		t.Fatalf("llr.Refresh() = (_, %v), want (_, nil)", err)
	}
	want := &loglist3.LogList{Operators: []*loglist3.Operator{{Name: "Google"}}}
	if diff := cmp.Diff(want, got.List); diff != "" {
		t.Fatalf("llr.Refresh() LogList diff (-want +got):\n%s", diff)
	}
}

func TestNewVerifiedLogListRefresherRejectsBadSignature(t *testing.T) {
	llPath, err := createTempFile(`{"operators": [{"id":0,"name":"Google"}]}`)
	if err != nil {
		t.Fatalf("createTempFile() = %v, want nil", err)
	}
	sigPath, err := createTempBytesFile([]byte("not-a-valid-signature"))
	if err != nil {
		if rmErr := os.Remove(llPath); rmErr != nil {
			t.Fatalf("createTempBytesFile() = %v; cleanup err = %v", err, rmErr)
		}
		t.Fatalf("createTempBytesFile() = %v, want nil", err)
	}
	defer func() {
		if err := os.Remove(llPath); err != nil {
			t.Fatalf("Operation to remove temp file failed: %v", err)
		}
		if err := os.Remove(sigPath); err != nil {
			t.Fatalf("Operation to remove temp file failed: %v", err)
		}
	}()

	llr, err := NewVerifiedLogListRefresher(llPath, sigPath, chromeLogListPublicKeyPEM)
	if err != nil {
		t.Fatalf("NewVerifiedLogListRefresher() = (_, %v), want (_, nil)", err)
	}
	if _, err := llr.Refresh(); err == nil || !strings.Contains(err.Error(), "failed to verify") {
		t.Fatalf("llr.Refresh() = (_, %v), want err containing %q", err, "failed to verify")
	}
}

func TestNewLogListRefresher(t *testing.T) {
	testCases := []struct {
		name      string
		ll        string
		wantLl    *loglist3.LogList
		errRegexp *regexp.Regexp
	}{
		{
			name:   "SuccessfulRead",
			ll:     `{"operators": [{"id":0,"name":"Google"}]}`,
			wantLl: &loglist3.LogList{Operators: []*loglist3.Operator{{Name: "Google"}}},
		},
		{
			name:      "CannotParseInput",
			ll:        `invalid`,
			errRegexp: regexp.MustCompile("failed to parse"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := createTempFile(tc.ll)
			if err != nil {
				t.Fatalf("createTempFile(%q) = (_, %q), want (_, nil)", tc.ll, err)
			}
			defer func() {
				if err := os.Remove(f); err != nil {
					t.Fatalf("Operation to remove temp file failed: %v", err)
				}
			}()

			beforeRefresh := time.Now()
			llr := NewLogListRefresher(f)
			ll, err := llr.Refresh()
			afterRefresh := time.Now()
			if gotErr, wantErr := err != nil, tc.errRegexp != nil; gotErr != wantErr {
				t.Fatalf("llr.Refresh() = (_, %v), want err? %t", err, wantErr)
			} else if gotErr && !tc.errRegexp.MatchString(err.Error()) {
				t.Fatalf("llr.Refresh() = (_, %q), want err to match regexp %q", err, tc.errRegexp)
			}
			if (ll == nil) != (tc.wantLl == nil) {
				t.Fatalf("llr.Refresh() = (%v, _), expected value? %t", ll, tc.wantLl != nil)
			}
			if ll == nil {
				return
			}
			if diff := cmp.Diff(ll.List, tc.wantLl); diff != "" {
				t.Errorf("llr.Refresh() LogList: diff -want +got\n%s", diff)
			}
			if diff := cmp.Diff(ll.JSON, []byte(tc.ll)); diff != "" {
				t.Errorf("llr.Refresh() JSON: diff -want +got\n%s", diff)
			}
			if !beforeRefresh.Before(ll.DownloadTime) || !afterRefresh.After(ll.DownloadTime) {
				t.Errorf("llr.Refresh() DownloadTime %s: outside of (%s, %s) interval", ll.DownloadTime, beforeRefresh, afterRefresh)
			}
		})
	}
}

func TestNewLogListRefresherUpdate(t *testing.T) {
	testCases := []struct {
		name      string
		ll        string
		llNext    string
		wantLl    *loglist3.LogList
		errRegexp *regexp.Regexp
	}{
		{
			name:      "NoUpdate",
			ll:        `{"operators": [{"id":0,"name":"Google"}]}`,
			llNext:    `{"operators": [{"id":0,"name":"Google"}]}`,
			wantLl:    nil,
			errRegexp: nil,
		},
		{
			name:      "LogListUpdated",
			ll:        `{"operators": [{"id":0,"name":"Google"}]}`,
			llNext:    `{"operators": [{"id":0,"name":"GoogleOps"}]}`,
			wantLl:    &loglist3.LogList{Operators: []*loglist3.Operator{{Name: "GoogleOps"}}},
			errRegexp: nil,
		},
		{
			name:      "CannotParseInput",
			ll:        `{"operators": [{"id":0,"name":"Google"}]}`,
			llNext:    `invalid`,
			errRegexp: regexp.MustCompile("failed to parse"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := createTempFile(tc.ll)
			if err != nil {
				t.Fatalf("createTempFile(%q) = (_, %q), want (_, nil)", tc.ll, err)
			}
			defer func() {
				if err := os.Remove(f); err != nil {
					t.Fatalf("Operation to remove temp file failed: %v", err)
				}
			}()

			llr := NewLogListRefresher(f)
			if _, err := llr.Refresh(); err != nil {
				t.Fatalf("llr.Refresh() = (_, %v), want (_, nil)", err)
			}

			// Simulate Log list update.
			if err := os.WriteFile(f, []byte(tc.llNext), 0755); err != nil {
				t.Fatalf("os.WriteFile(%q, %q) = %q, want nil", f, tc.llNext, err)
			}

			beforeRefresh := time.Now()
			ll, err := llr.Refresh()
			afterRefresh := time.Now()
			if gotErr, wantErr := err != nil, tc.errRegexp != nil; gotErr != wantErr {
				t.Fatalf("llr.Refresh() = (_, %v), want err? %t", err, wantErr)
			} else if gotErr && !tc.errRegexp.MatchString(err.Error()) {
				t.Fatalf("llr.Refresh() = (_, %q), want err to match regexp %q", err, tc.errRegexp)
			}
			if llNil, wantNil := ll == nil, tc.wantLl == nil; llNil != wantNil {
				t.Fatalf("llr.Refresh() = (%v, _), expected nil? %t", ll, wantNil)
			}
			if ll == nil {
				return
			}
			if diff := cmp.Diff(tc.wantLl, ll.List); diff != "" {
				t.Errorf("llr.Refresh(): diff -want +got\n%s", diff)
			}
			if diff := cmp.Diff(ll.JSON, []byte(tc.llNext)); diff != "" {
				t.Errorf("llr.Refresh() JSON: diff -want +got\n%s", diff)
			}
			if !beforeRefresh.Before(ll.DownloadTime) || !afterRefresh.After(ll.DownloadTime) {
				t.Errorf("llr.Refresh() DownloadTime %s: outside of (%s, %s) interval", ll.DownloadTime, beforeRefresh, afterRefresh)
			}
		})
	}
}
