// Copyright 2016 Google LLC. All Rights Reserved.
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

package ctfe

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/trillian/mockclient"
	"github.com/google/certificate-transparency-go/trillian/testdata"
	"github.com/google/certificate-transparency-go/trillian/util"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/trillian"
	"github.com/google/trillian/monitoring"
	"github.com/google/trillian/types"
	"github.com/kylelemons/godebug/pretty"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"k8s.io/klog/v2"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/trillian/ctfe/configpb"
	cttestonly "github.com/google/certificate-transparency-go/trillian/ctfe/testonly"
)

// Arbitrary time for use in tests
var fakeTime = time.Date(2016, 7, 22, 11, 01, 13, 0, time.UTC)
var fakeTimeMillis = uint64(fakeTime.UnixNano() / millisPerNano)

// The deadline should be the above bumped by 500ms
var fakeDeadlineTime = time.Date(2016, 7, 22, 11, 01, 13, 500*1000*1000, time.UTC)
var fakeTimeSource = util.NewFixedTimeSource(fakeTime)

const caCertB64 string = `MIIC0DCCAjmgAwIBAgIBADANBgkqhkiG9w0BAQUFADBVMQswCQYDVQQGEwJHQjEk
MCIGA1UEChMbQ2VydGlmaWNhdGUgVHJhbnNwYXJlbmN5IENBMQ4wDAYDVQQIEwVX
YWxlczEQMA4GA1UEBxMHRXJ3IFdlbjAeFw0xMjA2MDEwMDAwMDBaFw0yMjA2MDEw
MDAwMDBaMFUxCzAJBgNVBAYTAkdCMSQwIgYDVQQKExtDZXJ0aWZpY2F0ZSBUcmFu
c3BhcmVuY3kgQ0ExDjAMBgNVBAgTBVdhbGVzMRAwDgYDVQQHEwdFcncgV2VuMIGf
MA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDVimhTYhCicRmTbneDIRgcKkATxtB7
jHbrkVfT0PtLO1FuzsvRyY2RxS90P6tjXVUJnNE6uvMa5UFEJFGnTHgW8iQ8+EjP
KDHM5nugSlojgZ88ujfmJNnDvbKZuDnd/iYx0ss6hPx7srXFL8/BT/9Ab1zURmnL
svfP34b7arnRsQIDAQABo4GvMIGsMB0GA1UdDgQWBBRfnYgNyHPmVNT4DdjmsMEk
tEfDVTB9BgNVHSMEdjB0gBRfnYgNyHPmVNT4DdjmsMEktEfDVaFZpFcwVTELMAkG
A1UEBhMCR0IxJDAiBgNVBAoTG0NlcnRpZmljYXRlIFRyYW5zcGFyZW5jeSBDQTEO
MAwGA1UECBMFV2FsZXMxEDAOBgNVBAcTB0VydyBXZW6CAQAwDAYDVR0TBAUwAwEB
/zANBgkqhkiG9w0BAQUFAAOBgQAGCMxKbWTyIF4UbASydvkrDvqUpdryOvw4BmBt
OZDQoeojPUApV2lGOwRmYef6HReZFSCa6i4Kd1F2QRIn18ADB8dHDmFYT9czQiRy
f1HWkLxHqd81TbD26yWVXeGJPE3VICskovPkQNJ0tU4b03YmnKliibduyqQQkOFP
OwqULg==`

const intermediateCertB64 string = `MIIC3TCCAkagAwIBAgIBCTANBgkqhkiG9w0BAQUFADBVMQswCQYDVQQGEwJHQjEk
MCIGA1UEChMbQ2VydGlmaWNhdGUgVHJhbnNwYXJlbmN5IENBMQ4wDAYDVQQIEwVX
YWxlczEQMA4GA1UEBxMHRXJ3IFdlbjAeFw0xMjA2MDEwMDAwMDBaFw0yMjA2MDEw
MDAwMDBaMGIxCzAJBgNVBAYTAkdCMTEwLwYDVQQKEyhDZXJ0aWZpY2F0ZSBUcmFu
c3BhcmVuY3kgSW50ZXJtZWRpYXRlIENBMQ4wDAYDVQQIEwVXYWxlczEQMA4GA1UE
BxMHRXJ3IFdlbjCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA12pnjRFvUi5V
/4IckGQlCLcHSxTXcRWQZPeSfv3tuHE1oTZe594Yy9XOhl+GDHj0M7TQ09NAdwLn
o+9UKx3+m7qnzflNxZdfxyn4bxBfOBskNTXPnIAPXKeAwdPIRADuZdFu6c9S24rf
/lD1xJM1CyGQv1DVvDbzysWo2q6SzYsCAwEAAaOBrzCBrDAdBgNVHQ4EFgQUllUI
BQJ4R56Hc3ZBMbwUOkfiKaswfQYDVR0jBHYwdIAUX52IDchz5lTU+A3Y5rDBJLRH
w1WhWaRXMFUxCzAJBgNVBAYTAkdCMSQwIgYDVQQKExtDZXJ0aWZpY2F0ZSBUcmFu
c3BhcmVuY3kgQ0ExDjAMBgNVBAgTBVdhbGVzMRAwDgYDVQQHEwdFcncgV2VuggEA
MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADgYEAIgbascZrcdzglcP2qi73
LPd2G+er1/w5wxpM/hvZbWc0yoLyLd5aDIu73YJde28+dhKtjbMAp+IRaYhgIyYi
hMOqXSGR79oQv5I103s6KjQNWUGblKSFZvP6w82LU9Wk6YJw6tKXsHIQ+c5KITix
iBEUO5P6TnqH3TfhOF8sKQg=`

const caAndIntermediateCertsPEM = "-----BEGIN CERTIFICATE-----\n" +
	caCertB64 +
	"\n-----END CERTIFICATE-----\n" +
	"\n-----BEGIN CERTIFICATE-----\n" +
	intermediateCertB64 +
	"\n-----END CERTIFICATE-----\n"

const remoteQuotaUser = "Moneybags"

type handlerTestInfo struct {
	mockCtrl *gomock.Controller
	roots    *x509util.PEMCertPool
	client   *mockclient.MockTrillianLogClient
	li       *logInfo
}

const certQuotaPrefix = "CERT:"

func quotaUserForCert(c *x509.Certificate) string {
	return fmt.Sprintf("%s %s", certQuotaPrefix, c.Subject.String())
}

func quotaUsersForIssuers(t *testing.T, pem ...string) []string {
	t.Helper()
	r := make([]string, 0)
	for _, p := range pem {
		c, err := x509util.CertificateFromPEM([]byte(p))
		if x509.IsFatal(err) {
			t.Fatalf("Failed to parse pem: %v", err)
		}
		r = append(r, quotaUserForCert(c))
	}
	return r
}

func (info *handlerTestInfo) setRemoteQuotaUser(u string) {
	if len(u) > 0 {
		info.li.instanceOpts.RemoteQuotaUser = func(_ *http.Request) string { return u }
	} else {
		info.li.instanceOpts.RemoteQuotaUser = nil
	}
}

func (info *handlerTestInfo) enableCertQuota(e bool) {
	if e {
		info.li.instanceOpts.CertificateQuotaUser = quotaUserForCert
	} else {
		info.li.instanceOpts.CertificateQuotaUser = nil
	}
}

// setupTest creates mock objects and contexts.  Caller should invoke info.mockCtrl.Finish().
func setupTest(t *testing.T, pemRoots []string, signer crypto.Signer) handlerTestInfo {
	t.Helper()
	info := handlerTestInfo{
		mockCtrl: gomock.NewController(t),
		roots:    x509util.NewPEMCertPool(),
	}

	info.client = mockclient.NewMockTrillianLogClient(info.mockCtrl)
	vOpts := CertValidationOpts{
		trustedRoots:  info.roots,
		rejectExpired: false,
	}

	cfg := &configpb.LogConfig{LogId: 0x42, Prefix: "test", IsMirror: false}
	vCfg := &ValidatedLogConfig{Config: cfg}
	iOpts := InstanceOptions{Validated: vCfg, Client: info.client, Deadline: time.Millisecond * 500, MetricFactory: monitoring.InertMetricFactory{}, RequestLog: new(DefaultRequestLog)}
	info.li = newLogInfo(iOpts, vOpts, signer, fakeTimeSource, &directIssuanceChainService{})

	for _, pemRoot := range pemRoots {
		if !info.roots.AppendCertsFromPEM([]byte(pemRoot)) {
			klog.Fatal("failed to load cert pool")
		}
	}

	return info
}

func (info handlerTestInfo) getHandlers() map[string]AppHandler {
	return map[string]AppHandler{
		"get-sth":             {Info: info.li, Handler: getSTH, Name: "GetSTH", Method: http.MethodGet},
		"get-sth-consistency": {Info: info.li, Handler: getSTHConsistency, Name: "GetSTHConsistency", Method: http.MethodGet},
		"get-proof-by-hash":   {Info: info.li, Handler: getProofByHash, Name: "GetProofByHash", Method: http.MethodGet},
		"get-entries":         {Info: info.li, Handler: getEntries, Name: "GetEntries", Method: http.MethodGet},
		"get-roots":           {Info: info.li, Handler: getRoots, Name: "GetRoots", Method: http.MethodGet},
		"get-entry-and-proof": {Info: info.li, Handler: getEntryAndProof, Name: "GetEntryAndProof", Method: http.MethodGet},
		"logV3JSON":           {Info: info.li, Handler: logV3JSON, Name: "LogV3JSON", Method: http.MethodGet},
	}
}

func (info handlerTestInfo) postHandlers() map[string]AppHandler {
	return map[string]AppHandler{
		"add-chain":     {Info: info.li, Handler: addChain, Name: "AddChain", Method: http.MethodPost},
		"add-pre-chain": {Info: info.li, Handler: addPreChain, Name: "AddPreChain", Method: http.MethodPost},
	}
}

func TestPostHandlersRejectGet(t *testing.T) {
	info := setupTest(t, []string{cttestonly.FakeCACertPEM}, nil)
	defer info.mockCtrl.Finish()

	// Anything in the post handler list should reject GET
	for path, handler := range info.postHandlers() {
		t.Run(path, func(t *testing.T) {
			s := httptest.NewServer(handler)
			defer s.Close()

			resp, err := http.Get(s.URL + "/ct/v1/" + path)
			if err != nil {
				t.Fatalf("http.Get(%s)=(_,%q); want (_,nil)", path, err)
			}
			if got, want := resp.StatusCode, http.StatusMethodNotAllowed; got != want {
				t.Errorf("http.Get(%s)=(%d,nil); want (%d,nil)", path, got, want)
			}
		})
	}
}

func TestGetHandlersRejectPost(t *testing.T) {
	info := setupTest(t, []string{cttestonly.FakeCACertPEM}, nil)
	defer info.mockCtrl.Finish()

	// Anything in the get handler list should reject POST.
	for path, handler := range info.getHandlers() {
		t.Run(path, func(t *testing.T) {
			s := httptest.NewServer(handler)
			defer s.Close()

			resp, err := http.Post(s.URL+"/ct/v1/"+path, "application/json", nil)
			if err != nil {
				t.Fatalf("http.Post(%s)=(_,%q); want (_,nil)", path, err)
			}
			if got, want := resp.StatusCode, http.StatusMethodNotAllowed; got != want {
				t.Errorf("http.Post(%s)=(%d,nil); want (%d,nil)", path, got, want)
			}
		})
	}
}

func TestPostHandlersFailure(t *testing.T) {
	var tests = []struct {
		descr string
		body  func() io.Reader
		want  int
	}{
		{"nil", func() io.Reader { return nil }, http.StatusBadRequest},
		{"''", func() io.Reader { return strings.NewReader("") }, http.StatusBadRequest},
		{"malformed-json", func() io.Reader { return strings.NewReader("{ !$%^& not valid json ") }, http.StatusBadRequest},
		{"empty-chain", func() io.Reader { return strings.NewReader(`{ "chain": [] }`) }, http.StatusBadRequest},
		{"wrong-chain", func() io.Reader { return strings.NewReader(`{ "chain": [ "test" ] }`) }, http.StatusBadRequest},
		{"too-large-body", func() io.Reader {
			return strings.NewReader(fmt.Sprintf(`{ "chain": [ "%s" ] }`, strings.Repeat("A", 600000)))
		}, http.StatusRequestEntityTooLarge},
	}

	info := setupTest(t, []string{cttestonly.FakeCACertPEM}, nil)
	defer info.mockCtrl.Finish()
	maxCertChainSize := int64(500 * 1024)
	for path, handler := range info.postHandlers() {
		t.Run(path, func(t *testing.T) {
			var wrappedHandler http.Handler
			if path == "add-chain" || path == "add-pre-chain" {
				wrappedHandler = http.MaxBytesHandler(http.Handler(handler), maxCertChainSize)
			} else {
				wrappedHandler = handler
			}

			s := httptest.NewServer(wrappedHandler)
			defer s.Close()

			for _, test := range tests {
				resp, err := http.Post(s.URL+"/ct/v1/"+path, "application/json", test.body())
				if err != nil {
					t.Errorf("http.Post(%s,%s)=(_,%q); want (_,nil)", path, test.descr, err)
					continue
				}
				if resp.StatusCode != test.want {
					t.Errorf("http.Post(%s,%s)=(%d,nil); want (%d,nil)", path, test.descr, resp.StatusCode, test.want)
				}
			}
		})
	}
}

func TestHandlers(t *testing.T) {
	path := "/test-prefix/ct/v1/add-chain"
	info := setupTest(t, nil, nil)
	defer info.mockCtrl.Finish()
	for _, test := range []string{
		"/test-prefix/",
		"test-prefix/",
		"/test-prefix",
		"test-prefix",
	} {
		t.Run(test, func(t *testing.T) {
			handlers := info.li.Handlers(test)
			if h, ok := handlers[path]; !ok {
				t.Errorf("Handlers(%s)[%q]=%+v; want _", test, path, h)
			} else if h.Name != "AddChain" {
				t.Errorf("Handlers(%s)[%q].Name=%q; want 'AddChain'", test, path, h.Name)
			}
			// Check each entrypoint has a handler
			if got, want := len(handlers), len(Entrypoints); got != want {
				t.Fatalf("len(Handlers(%s))=%d; want %d", test, got, want)
			}

			// We want to see the same set of handler names that we think we registered.
			var hNames []EntrypointName
			for _, v := range handlers {
				hNames = append(hNames, v.Name)
			}

			if !cmp.Equal(Entrypoints, hNames, cmpopts.SortSlices(func(n1, n2 EntrypointName) bool {
				return n1 < n2
			})) {
				t.Errorf("Handler names mismatch got: %v, want: %v", hNames, Entrypoints)
			}
		})
	}
}

func TestGetRoots(t *testing.T) {
	info := setupTest(t, []string{caAndIntermediateCertsPEM}, nil)
	defer info.mockCtrl.Finish()
	handler := AppHandler{Info: info.li, Handler: getRoots, Name: "GetRoots", Method: http.MethodGet}

	req, err := http.NewRequest(http.MethodGet, "http://example.com/ct/v1/get-roots", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if got, want := w.Code, http.StatusOK; got != want {
		t.Fatalf("http.Get(get-roots)=%d; want %d", got, want)
	}

	var parsedJSON map[string][]string
	if err := json.Unmarshal(w.Body.Bytes(), &parsedJSON); err != nil {
		t.Fatalf("json.Unmarshal(%q)=%q; want nil", w.Body.Bytes(), err)
	}
	if got := len(parsedJSON); got != 1 {
		t.Errorf("len(json)=%d; want 1", got)
	}
	certs := parsedJSON[jsonMapKeyCertificates]
	if got := len(certs); got != 2 {
		t.Fatalf("len(%q)=%d; want 2", certs, got)
	}
	if got, want := certs[0], strings.ReplaceAll(caCertB64, "\n", ""); got != want {
		t.Errorf("certs[0]=%s; want %s", got, want)
	}
	if got, want := certs[1], strings.ReplaceAll(intermediateCertB64, "\n", ""); got != want {
		t.Errorf("certs[1]=%s; want %s", got, want)
	}
}

func TestAddChainWhitespace(t *testing.T) {
	signer, err := setupSigner(fakeSignature)
	if err != nil {
		t.Fatalf("Failed to create test signer: %v", err)
	}

	info := setupTest(t, []string{cttestonly.FakeCACertPEM}, signer)
	defer info.mockCtrl.Finish()

	// Throughout we use variants of a hard-coded POST body derived from a chain of:
	pemChain := []string{cttestonly.LeafSignedByFakeIntermediateCertPEM, cttestonly.FakeIntermediateCertPEM}

	// Break the JSON into chunks:
	intro := "{\"chain\""
	// followed by colon then the first line of the PEM file
	chunk1a := "[\"MIIH6DCCBtCgAwIBAgIIQoIqW4Zvv+swDQYJKoZIhvcNAQELBQAwcjELMAkGA1UE"
	// straight into rest of first entry
	chunk1b := "BhMCR0IxDzANBgNVBAgMBkxvbmRvbjEPMA0GA1UEBwwGTG9uZG9uMQ8wDQYDVQQKDAZHb29nbGUxDDAKBgNVBAsMA0VuZzEiMCAGA1UEAwwZRmFrZUludGVybWVkaWF0ZUF1dGhvcml0eTAeFw0xNjA1MTMxNDI2NDRaFw0xOTA3MTIxNDI2NDRaMIIBWDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxEzARBgNVBAoMCkdvb2dsZSBJbmMxFTATBgNVBAMMDCouZ29vZ2xlLmNvbTGBwzCBwAYDVQQEDIG4UkZDNTI4MCBzNC4yLjEuOSAnVGhlIHBhdGhMZW5Db25zdHJhaW50IGZpZWxkIC4uLiBnaXZlcyB0aGUgbWF4aW11bSBudW1iZXIgb2Ygbm9uLXNlbGYtaXNzdWVkIGludGVybWVkaWF0ZSBjZXJ0aWZpY2F0ZXMgdGhhdCBtYXkgZm9sbG93IHRoaXMgY2VydGlmaWNhdGUgaW4gYSB2YWxpZCBjZXJ0aWZpY2F0aW9uIHBhdGguJzEqMCgGA1UEKgwhSW50ZXJtZWRpYXRlIENBIGNlcnQgdXNlZCB0byBzaWduMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExAk5hPUVjRJUsgKc+QHibTVH1A3QEWFmCTUdyxIUlbI//zW9Io5N/DhQLSLWmB7KoCOvpJZ+MtGCXzFX+yj/N6OCBGMwggRfMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjCCA0IGA1UdEQSCAzkwggM1ggwqLmdvb2dsZS5jb22CDSouYW5kcm9pZC5jb22CFiouYXBwZW5naW5lLmdvb2dsZS5jb22CEiouY2xvdWQuZ29vZ2xlLmNvbYIWKi5nb29nbGUtYW5hbHl0aWNzLmNvbYILKi5nb29nbGUuY2GCCyouZ29vZ2xlLmNsgg4qLmdvb2dsZS5jby5pboIOKi5nb29nbGUuY28uanCCDiouZ29vZ2xlLmNvLnVrgg8qLmdvb2dsZS5jb20uYXKCDyouZ29vZ2xlLmNvbS5hdYIPKi5nb29nbGUuY29tLmJygg8qLmdvb2dsZS5jb20uY2+CDyouZ29vZ2xlLmNvbS5teIIPKi5nb29nbGUuY29tLnRygg8qLmdvb2dsZS5jb20udm6CCyouZ29vZ2xlLmRlggsqLmdvb2dsZS5lc4ILKi5nb29nbGUuZnKCCyouZ29vZ2xlLmh1ggsqLmdvb2dsZS5pdIILKi5nb29nbGUubmyCCyouZ29vZ2xlLnBsggsqLmdvb2dsZS5wdIISKi5nb29nbGVhZGFwaXMuY29tgg8qLmdvb2dsZWFwaXMuY26CFCouZ29vZ2xlY29tbWVyY2UuY29tghEqLmdvb2dsZXZpZGVvLmNvbYIMKi5nc3RhdGljLmNugg0qLmdzdGF0aWMuY29tggoqLmd2dDEuY29tggoqLmd2dDIuY29tghQqLm1ldHJpYy5nc3RhdGljLmNvbYIMKi51cmNoaW4uY29tghAqLnVybC5nb29nbGUuY29tghYqLnlvdXR1YmUtbm9jb29raWUuY29tgg0qLnlvdXR1YmUuY29tghYqLnlvdXR1YmVlZHVjYXRpb24uY29tggsqLnl0aW1nLmNvbYIaYW5kcm9pZC5jbGllbnRzLmdvb2dsZS5jb22CC2FuZHJvaWQuY29tggRnLmNvggZnb28uZ2yCFGdvb2dsZS1hbmFseXRpY3MuY29tggpnb29nbGUuY29tghJnb29nbGVjb21tZXJjZS5jb22CCnVyY2hpbi5jb22CCHlvdXR1LmJlggt5b3V0dWJlLmNvbYIUeW91dHViZWVkdWNhdGlvbi5jb20wDAYDVR0PBAUDAweAADBoBggrBgEFBQcBAQRcMFowKwYIKwYBBQUHMAKGH2h0dHA6Ly9wa2kuZ29vZ2xlLmNvbS9HSUFHMi5jcnQwKwYIKwYBBQUHMAGGH2h0dHA6Ly9jbGllbnRzMS5nb29nbGUuY29tL29jc3AwHQYDVR0OBBYEFNv0bmPu4ty+vzhgT5gx0GRE8WPYMAwGA1UdEwEB/wQCMAAwIQYDVR0gBBowGDAMBgorBgEEAdZ5AgUBMAgGBmeBDAECAjAwBgNVHR8EKTAnMCWgI6Ahhh9odHRwOi8vcGtpLmdvb2dsZS5jb20vR0lBRzIuY3JsMA0GCSqGSIb3DQEBCwUAA4IBAQAOpm95fThLYPDBdpxOkvUkzhI0cpSVjc8cDNZ4a+5mK1A2Inq+/yLH3ZMsQIMvoDcpj7uYIr+Oxmy0i4/pHg+9it/f9cmqeawA5sqmGnSOZ/lfCYI8+bRbMIULrijCuJwjfGpZZsqOvSBuIOSzRvgGVplcs0dituT2khCFrkblwa/BqIqztvP7LuEmVpjkqt4pC3HvD0XUxs5PIdZZGInfeqymk5feReWHBuPHpPIUObKxmQt+hcw6YsHE+0B84Xtx9BMe4qqUfrqmtWXn9unBwxqSYsCqxHQpQ+70pmuBxlB9s6LStIzE9syaDmUyjxRljKAwINV6z0j7hKQ6MPpE\""
	// followed by comma then
	chunk2 := "\"MIIDnTCCAoWgAwIBAgIIQoIqW4Zvv+swDQYJKoZIhvcNAQELBQAwcTELMAkGA1UEBhMCR0IxDzANBgNVBAgMBkxvbmRvbjEPMA0GA1UEBwwGTG9uZG9uMQ8wDQYDVQQKDAZHb29nbGUxDDAKBgNVBAsMA0VuZzEhMB8GA1UEAwwYRmFrZUNlcnRpZmljYXRlQXV0aG9yaXR5MB4XDTE2MDUxMzE0MjY0NFoXDTE5MDcxMjE0MjY0NFowcjELMAkGA1UEBhMCR0IxDzANBgNVBAgMBkxvbmRvbjEPMA0GA1UEBwwGTG9uZG9uMQ8wDQYDVQQKDAZHb29nbGUxDDAKBgNVBAsMA0VuZzEiMCAGA1UEAwwZRmFrZUludGVybWVkaWF0ZUF1dGhvcml0eTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMqkDHpt6SYi1GcZyClAxr3LRDnn+oQBHbMEFUg3+lXVmEsq/xQO1s4naynV6I05676XvlMh0qPyJ+9GaBxvhHeFtGh4etQ9UEmJj55rSs50wA/IaDh+roKukQxthyTESPPgjqg+DPjh6H+h3Sn00Os6sjh3DxpOphTEsdtb7fmk8J0e2KjQQCjW/GlECzc359b9KbBwNkcAiYFayVHPLaCAdvzYVyiHgXHkEEs5FlHyhe2gNEG/81Io8c3E3DH5JhT9tmVRL3bpgpT8Kr4aoFhU2LXe45YIB1A9DjUm5TrHZ+iNtvE0YfYMR9L9C1HPppmX1CahEhTdog7laE1198UCAwEAAaM4MDYwDwYDVR0jBAgwBoAEAQIDBDASBgNVHRMBAf8ECDAGAQH/AgEAMA8GA1UdDwEB/wQFAwMH/4AwDQYJKoZIhvcNAQELBQADggEBAAHiOgwAvEzhrNMQVAz8a+SsyMIABXQ5P8WbJeHjkIipE4+5ZpkrZVXq9p8wOdkYnOHx4WNi9PVGQbLG9Iufh9fpk8cyyRWDi+V20/CNNtawMq3ClV3dWC98Tj4WX/BXDCeY2jK4jYGV+ds43HYV0ToBmvvrccq/U7zYMGFcQiKBClz5bTE+GMvrZWcO5A/Lh38i2YSF1i8SfDVnAOBlAgZmllcheHpGsWfSnduIllUvTsRvEIsaaqfVLl5QpRXBOq8tbjK85/2g6ear1oxPhJ1w9hds+WTFXkmHkWvKJebY13t3OfSjAyhaRSt8hdzDzHTFwjPjHT8h6dU7/hMdkUg=\""
	epilog := "]}\n"

	// Which (if successful) produces a QueueLeaf response with a Merkle leaf:
	pool := loadCertsIntoPoolOrDie(t, pemChain)
	merkleLeaf, err := ct.MerkleTreeLeafFromChain(pool.RawCertificates(), ct.X509LogEntryType, fakeTimeMillis)
	if err != nil {
		t.Fatalf("Unexpected error signing SCT: %v", err)
	}
	// The generated LogLeaf will include the root cert as well.
	fullChain := make([]*x509.Certificate, len(pemChain)+1)
	copy(fullChain, pool.RawCertificates())
	fullChain[len(pemChain)] = info.roots.RawCertificates()[0]
	leaf := logLeafForCert(t, fullChain, merkleLeaf, false)
	queuedLeaf := &trillian.QueuedLogLeaf{
		Leaf:   leaf,
		Status: status.New(codes.OK, "ok").Proto(),
	}
	rsp := trillian.QueueLeafResponse{QueuedLeaf: queuedLeaf}
	req := &trillian.QueueLeafRequest{LogId: 0x42, Leaf: leaf}

	var tests = []struct {
		descr string
		body  string
		want  int
	}{
		{
			descr: "valid",
			body:  intro + ":" + chunk1a + chunk1b + "," + chunk2 + epilog,
			want:  http.StatusOK,
		},
		{
			descr: "valid-space-between",
			body:  intro + " : " + chunk1a + chunk1b + " , " + chunk2 + epilog,
			want:  http.StatusOK,
		},
		{
			descr: "valid-newline-between",
			body:  intro + " : " + chunk1a + chunk1b + ",\n" + chunk2 + epilog,
			want:  http.StatusOK,
		},
		{
			descr: "invalid-raw-newline-in-string",
			body:  intro + ":" + chunk1a + "\n" + chunk1b + "," + chunk2 + epilog,
			want:  http.StatusBadRequest,
		},
		{
			descr: "valid-escaped-newline-in-string",
			body:  intro + ":" + chunk1a + "\\n" + chunk1b + "," + chunk2 + epilog,
			want:  http.StatusOK,
		},
	}

	for _, test := range tests {
		t.Run(test.descr, func(t *testing.T) {
			if test.want == http.StatusOK {
				info.client.EXPECT().QueueLeaf(deadlineMatcher(), cmpMatcher{req}).Return(&rsp, nil)
			}

			recorder := httptest.NewRecorder()
			handler := AppHandler{Info: info.li, Handler: addChain, Name: "AddChain", Method: http.MethodPost}
			req, err := http.NewRequest(http.MethodPost, "http://example.com/ct/v1/add-chain", strings.NewReader(test.body))
			if err != nil {
				t.Fatalf("Failed to create POST request: %v", err)
			}
			handler.ServeHTTP(recorder, req)

			if recorder.Code != test.want {
				t.Fatalf("addChain()=%d (body:%v); want %dv", recorder.Code, recorder.Body, test.want)
			}
		})
	}
}

func TestAddChain(t *testing.T) {
	var tests = []struct {
		descr           string
		chain           []string
		toSign          string // hex-encoded
		want            int
		err             error
		remoteQuotaUser string
		enableCertQuota bool
		// if remote quota enabled, it must be the first entry here
		wantQuotaUsers []string
	}{
		{
			descr: "leaf-only",
			chain: []string{cttestonly.LeafSignedByFakeIntermediateCertPEM},
			want:  http.StatusBadRequest,
		},
		{
			descr: "wrong-entry-type",
			chain: []string{cttestonly.PrecertPEMValid},
			want:  http.StatusBadRequest,
		},
		{
			descr:  "backend-rpc-fail",
			chain:  []string{cttestonly.LeafSignedByFakeIntermediateCertPEM, cttestonly.FakeIntermediateCertPEM},
			toSign: "1337d72a403b6539f58896decba416d5d4b3603bfa03e1f94bb9b4e898af897d",
			want:   http.StatusInternalServerError,
			err:    status.Errorf(codes.Internal, "error"),
		},
		{
			descr:  "success-without-root",
			chain:  []string{cttestonly.LeafSignedByFakeIntermediateCertPEM, cttestonly.FakeIntermediateCertPEM},
			toSign: "1337d72a403b6539f58896decba416d5d4b3603bfa03e1f94bb9b4e898af897d",
			want:   http.StatusOK,
		},
		{
			descr:  "success",
			chain:  []string{cttestonly.LeafSignedByFakeIntermediateCertPEM, cttestonly.FakeIntermediateCertPEM, cttestonly.FakeCACertPEM},
			toSign: "1337d72a403b6539f58896decba416d5d4b3603bfa03e1f94bb9b4e898af897d",
			want:   http.StatusOK,
		},
		{
			descr:           "success-without-root with remote quota",
			chain:           []string{cttestonly.LeafSignedByFakeIntermediateCertPEM, cttestonly.FakeIntermediateCertPEM},
			toSign:          "1337d72a403b6539f58896decba416d5d4b3603bfa03e1f94bb9b4e898af897d",
			remoteQuotaUser: remoteQuotaUser,
			want:            http.StatusOK,
			wantQuotaUsers:  []string{remoteQuotaUser},
		},
		{
			descr:           "success with remote quota",
			chain:           []string{cttestonly.LeafSignedByFakeIntermediateCertPEM, cttestonly.FakeIntermediateCertPEM, cttestonly.FakeCACertPEM},
			toSign:          "1337d72a403b6539f58896decba416d5d4b3603bfa03e1f94bb9b4e898af897d",
			remoteQuotaUser: remoteQuotaUser,
			want:            http.StatusOK,
			wantQuotaUsers:  []string{remoteQuotaUser},
		},
		{
			descr:           "success with chain quota",
			chain:           []string{cttestonly.LeafSignedByFakeIntermediateCertPEM, cttestonly.FakeIntermediateCertPEM, cttestonly.FakeCACertPEM},
			toSign:          "1337d72a403b6539f58896decba416d5d4b3603bfa03e1f94bb9b4e898af897d",
			enableCertQuota: true,
			want:            http.StatusOK,
			wantQuotaUsers:  quotaUsersForIssuers(t, cttestonly.FakeIntermediateCertPEM, cttestonly.FakeCACertPEM),
		},
		{
			descr:           "success with remote and chain quota",
			chain:           []string{cttestonly.LeafSignedByFakeIntermediateCertPEM, cttestonly.FakeIntermediateCertPEM, cttestonly.FakeCACertPEM},
			toSign:          "1337d72a403b6539f58896decba416d5d4b3603bfa03e1f94bb9b4e898af897d",
			remoteQuotaUser: remoteQuotaUser,
			enableCertQuota: true,
			want:            http.StatusOK,
			wantQuotaUsers:  append([]string{remoteQuotaUser}, quotaUsersForIssuers(t, cttestonly.FakeIntermediateCertPEM, cttestonly.FakeCACertPEM)...),
		},
	}

	signer, err := setupSigner(fakeSignature)
	if err != nil {
		t.Fatalf("Failed to create test signer: %v", err)
	}

	info := setupTest(t, []string{cttestonly.FakeCACertPEM}, signer)
	defer info.mockCtrl.Finish()

	for _, test := range tests {
		t.Run(test.descr, func(t *testing.T) {
			info.setRemoteQuotaUser(test.remoteQuotaUser)
			info.enableCertQuota(test.enableCertQuota)
			pool := loadCertsIntoPoolOrDie(t, test.chain)
			chain := createJSONChain(t, *pool)
			if len(test.toSign) > 0 {
				root := info.roots.RawCertificates()[0]
				merkleLeaf, err := ct.MerkleTreeLeafFromChain(pool.RawCertificates(), ct.X509LogEntryType, fakeTimeMillis)
				if err != nil {
					t.Fatalf("Unexpected error signing SCT: %v", err)
				}
				leafChain := pool.RawCertificates()
				if !leafChain[len(leafChain)-1].Equal(root) {
					// The submitted chain may not include a root, but the generated LogLeaf will
					fullChain := make([]*x509.Certificate, len(leafChain)+1)
					copy(fullChain, leafChain)
					fullChain[len(leafChain)] = root
					leafChain = fullChain
				}
				leaf := logLeafForCert(t, leafChain, merkleLeaf, false)
				queuedLeaf := &trillian.QueuedLogLeaf{
					Leaf:   leaf,
					Status: status.New(codes.OK, "ok").Proto(),
				}
				rsp := trillian.QueueLeafResponse{QueuedLeaf: queuedLeaf}
				req := &trillian.QueueLeafRequest{LogId: 0x42, Leaf: leaf}
				if len(test.wantQuotaUsers) > 0 {
					req.ChargeTo = &trillian.ChargeTo{User: test.wantQuotaUsers}
				}
				info.client.EXPECT().QueueLeaf(deadlineMatcher(), cmpMatcher{req}).Return(&rsp, test.err)
			}

			recorder := makeAddChainRequest(t, info.li, chain)
			if recorder.Code != test.want {
				t.Fatalf("addChain()=%d (body:%v); want %dv", recorder.Code, recorder.Body, test.want)
			}
			if test.want == http.StatusOK {
				var resp ct.AddChainResponse
				if err := json.NewDecoder(recorder.Body).Decode(&resp); err != nil {
					t.Fatalf("json.Decode(%s)=%v; want nil", recorder.Body.Bytes(), err)
				}

				if got, want := ct.Version(resp.SCTVersion), ct.V1; got != want {
					t.Errorf("resp.SCTVersion=%v; want %v", got, want)
				}
				if got, want := resp.ID, demoLogID[:]; !bytes.Equal(got, want) {
					t.Errorf("resp.ID=%v; want %v", got, want)
				}
				if got, want := resp.Timestamp, uint64(1469185273000); got != want {
					t.Errorf("resp.Timestamp=%d; want %d", got, want)
				}
				if got, want := hex.EncodeToString(resp.Signature), "040300067369676e6564"; got != want {
					t.Errorf("resp.Signature=%s; want %s", got, want)
				}
			}
		})
	}
}

func TestAddPrechain(t *testing.T) {
	var tests = []struct {
		descr         string
		chain         []string
		root          string
		toSign        string // hex-encoded
		err           error
		want          int
		wantQuotaUser string
	}{
		{
			descr: "leaf-signed-by-different",
			chain: []string{cttestonly.PrecertPEMValid, cttestonly.FakeIntermediateCertPEM},
			want:  http.StatusBadRequest,
		},
		{
			descr: "wrong-entry-type",
			chain: []string{cttestonly.TestCertPEM},
			want:  http.StatusBadRequest,
		},
		{
			descr:  "backend-rpc-fail",
			chain:  []string{cttestonly.PrecertPEMValid, cttestonly.CACertPEM},
			toSign: "92ecae1a2dc67a6c5f9c96fa5cab4c2faf27c48505b696dad926f161b0ca675a",
			err:    status.Errorf(codes.Internal, "error"),
			want:   http.StatusInternalServerError,
		},
		{
			descr:  "success",
			chain:  []string{cttestonly.PrecertPEMValid, cttestonly.CACertPEM},
			toSign: "92ecae1a2dc67a6c5f9c96fa5cab4c2faf27c48505b696dad926f161b0ca675a",
			want:   http.StatusOK,
		},
		{
			descr:         "success with quota",
			chain:         []string{cttestonly.PrecertPEMValid, cttestonly.CACertPEM},
			toSign:        "92ecae1a2dc67a6c5f9c96fa5cab4c2faf27c48505b696dad926f161b0ca675a",
			want:          http.StatusOK,
			wantQuotaUser: remoteQuotaUser,
		},
		{
			descr:  "success-without-root",
			chain:  []string{cttestonly.PrecertPEMValid},
			toSign: "92ecae1a2dc67a6c5f9c96fa5cab4c2faf27c48505b696dad926f161b0ca675a",
			want:   http.StatusOK,
		},
		{
			descr:         "success-without-root with quota",
			chain:         []string{cttestonly.PrecertPEMValid},
			toSign:        "92ecae1a2dc67a6c5f9c96fa5cab4c2faf27c48505b696dad926f161b0ca675a",
			want:          http.StatusOK,
			wantQuotaUser: remoteQuotaUser,
		},
	}

	signer, err := setupSigner(fakeSignature)
	if err != nil {
		t.Fatalf("Failed to create test signer: %v", err)
	}

	info := setupTest(t, []string{cttestonly.CACertPEM}, signer)
	defer info.mockCtrl.Finish()

	for _, test := range tests {
		t.Run(test.descr, func(t *testing.T) {
			info.setRemoteQuotaUser(test.wantQuotaUser)
			pool := loadCertsIntoPoolOrDie(t, test.chain)
			chain := createJSONChain(t, *pool)
			if len(test.toSign) > 0 {
				root := info.roots.RawCertificates()[0]
				merkleLeaf, err := ct.MerkleTreeLeafFromChain([]*x509.Certificate{pool.RawCertificates()[0], root}, ct.PrecertLogEntryType, fakeTimeMillis)
				if err != nil {
					t.Fatalf("Unexpected error signing SCT: %v", err)
				}
				leafChain := pool.RawCertificates()
				if !leafChain[len(leafChain)-1].Equal(root) {
					// The submitted chain may not include a root, but the generated LogLeaf will
					fullChain := make([]*x509.Certificate, len(leafChain)+1)
					copy(fullChain, leafChain)
					fullChain[len(leafChain)] = root
					leafChain = fullChain
				}
				leaf := logLeafForCert(t, leafChain, merkleLeaf, true)
				queuedLeaf := &trillian.QueuedLogLeaf{
					Leaf:   leaf,
					Status: status.New(codes.OK, "ok").Proto(),
				}
				rsp := trillian.QueueLeafResponse{QueuedLeaf: queuedLeaf}
				req := &trillian.QueueLeafRequest{LogId: 0x42, Leaf: leaf}
				if len(test.wantQuotaUser) != 0 {
					req.ChargeTo = &trillian.ChargeTo{User: []string{test.wantQuotaUser}}
				}
				info.client.EXPECT().QueueLeaf(deadlineMatcher(), cmpMatcher{req}).Return(&rsp, test.err)
			}

			recorder := makeAddPrechainRequest(t, info.li, chain)
			if recorder.Code != test.want {
				t.Fatalf("addPrechain()=%d (body:%v); want %d", recorder.Code, recorder.Body, test.want)
			}
			if test.want == http.StatusOK {
				var resp ct.AddChainResponse
				if err := json.NewDecoder(recorder.Body).Decode(&resp); err != nil {
					t.Fatalf("json.Decode(%s)=%v; want nil", recorder.Body.Bytes(), err)
				}

				if got, want := ct.Version(resp.SCTVersion), ct.V1; got != want {
					t.Errorf("resp.SCTVersion=%v; want %v", got, want)
				}
				if got, want := resp.ID, demoLogID[:]; !bytes.Equal(got, want) {
					t.Errorf("resp.ID=%x; want %x", got, want)
				}
				if got, want := resp.Timestamp, uint64(1469185273000); got != want {
					t.Errorf("resp.Timestamp=%d; want %d", got, want)
				}
				if got, want := hex.EncodeToString(resp.Signature), "040300067369676e6564"; got != want {
					t.Errorf("resp.Signature=%s; want %s", got, want)
				}
			}
		})
	}
}

func TestGetSTH(t *testing.T) {
	var tests = []struct {
		descr         string
		rpcRsp        *trillian.GetLatestSignedLogRootResponse
		rpcErr        error
		toSign        string // hex-encoded
		signErr       error
		want          int
		wantQuotaUser string
		errStr        string
	}{
		{
			descr:  "backend-failure",
			rpcErr: errors.New("backendfailure"),
			want:   http.StatusInternalServerError,
			errStr: "backendfailure",
		},
		{
			descr:  "backend-unimplemented",
			rpcErr: status.Errorf(codes.Unimplemented, "no-such-thing"),
			want:   http.StatusNotImplemented,
			errStr: "no-such-thing",
		},
		{
			descr:  "bad-hash",
			rpcRsp: makeGetRootResponseForTest(t, 12345, 25, []byte("thisisnot32byteslong")),
			want:   http.StatusInternalServerError,
			errStr: "bad hash size",
		},
		{
			descr:   "signer-fail",
			rpcRsp:  makeGetRootResponseForTest(t, 12345, 25, []byte("abcdabcdabcdabcdabcdabcdabcdabcd")),
			want:    http.StatusInternalServerError,
			signErr: errors.New("signerfails"),
			errStr:  "signerfails",
		},
		{
			descr:  "ok",
			rpcRsp: makeGetRootResponseForTest(t, 12345000000, 25, []byte("abcdabcdabcdabcdabcdabcdabcdabcd")),
			toSign: "1e88546f5157bfaf77ca2454690b602631fedae925bbe7cf708ea275975bfe74",
			want:   http.StatusOK,
		},
		{
			descr:         "ok with quota",
			rpcRsp:        makeGetRootResponseForTest(t, 12345000000, 25, []byte("abcdabcdabcdabcdabcdabcdabcdabcd")),
			toSign:        "1e88546f5157bfaf77ca2454690b602631fedae925bbe7cf708ea275975bfe74",
			want:          http.StatusOK,
			wantQuotaUser: remoteQuotaUser,
		},
	}

	block, _ := pem.Decode([]byte(testdata.DemoPublicKey))
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to load public key: %v", err)
	}

	for _, test := range tests {
		// Run deferred funcs at the end of each iteration.
		func() {
			var signer crypto.Signer
			if test.signErr != nil {
				signer = testdata.NewSignerWithErr(key, test.signErr)
			} else {
				signer = testdata.NewSignerWithFixedSig(key, fakeSignature)
			}

			info := setupTest(t, []string{cttestonly.CACertPEM}, signer)
			info.setRemoteQuotaUser(test.wantQuotaUser)
			defer info.mockCtrl.Finish()

			srReq := &trillian.GetLatestSignedLogRootRequest{LogId: 0x42}
			if len(test.wantQuotaUser) != 0 {
				srReq.ChargeTo = &trillian.ChargeTo{User: []string{test.wantQuotaUser}}
			}
			info.client.EXPECT().GetLatestSignedLogRoot(deadlineMatcher(), cmpMatcher{srReq}).Return(test.rpcRsp, test.rpcErr)
			req, err := http.NewRequest(http.MethodGet, "http://example.com/ct/v1/get-sth", nil)
			if err != nil {
				t.Errorf("Failed to create request: %v", err)
				return
			}

			handler := AppHandler{Info: info.li, Handler: getSTH, Name: "GetSTH", Method: http.MethodGet}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if got := w.Code; got != test.want {
				t.Errorf("GetSTH(%s).Code=%d; want %d", test.descr, got, test.want)
			}
			if test.errStr != "" {
				if body := w.Body.String(); !strings.Contains(body, test.errStr) {
					t.Errorf("GetSTH(%s)=%q; want to find %q", test.descr, body, test.errStr)
				}
				return
			}

			var rsp ct.GetSTHResponse
			if err := json.Unmarshal(w.Body.Bytes(), &rsp); err != nil {
				t.Errorf("Failed to unmarshal json response: %s", w.Body.Bytes())
				return
			}

			if got, want := rsp.TreeSize, uint64(25); got != want {
				t.Errorf("GetSTH(%s).TreeSize=%d; want %d", test.descr, got, want)
			}
			if got, want := rsp.Timestamp, uint64(12345); got != want {
				t.Errorf("GetSTH(%s).Timestamp=%d; want %d", test.descr, got, want)
			}
			if got, want := hex.EncodeToString(rsp.SHA256RootHash), "6162636461626364616263646162636461626364616263646162636461626364"; got != want {
				t.Errorf("GetSTH(%s).SHA256RootHash=%s; want %s", test.descr, got, want)
			}
			if got, want := hex.EncodeToString(rsp.TreeHeadSignature), "040300067369676e6564"; got != want {
				t.Errorf("GetSTH(%s).TreeHeadSignature=%s; want %s", test.descr, got, want)
			}
		}()
	}
}

func TestGetEntries(t *testing.T) {
	// Create a couple of valid serialized ct.MerkleTreeLeaf objects
	merkleLeaf1 := ct.MerkleTreeLeaf{
		Version:  ct.V1,
		LeafType: ct.TimestampedEntryLeafType,
		TimestampedEntry: &ct.TimestampedEntry{
			Timestamp:  12345,
			EntryType:  ct.X509LogEntryType,
			X509Entry:  &ct.ASN1Cert{Data: []byte("certdatacertdata")},
			Extensions: ct.CTExtensions{},
		},
	}
	merkleLeaf2 := ct.MerkleTreeLeaf{
		Version:  ct.V1,
		LeafType: ct.TimestampedEntryLeafType,
		TimestampedEntry: &ct.TimestampedEntry{
			Timestamp:  67890,
			EntryType:  ct.X509LogEntryType,
			X509Entry:  &ct.ASN1Cert{Data: []byte("certdat2certdat2")},
			Extensions: ct.CTExtensions{},
		},
	}
	merkleBytes1, err1 := tls.Marshal(merkleLeaf1)
	merkleBytes2, err2 := tls.Marshal(merkleLeaf2)
	if err1 != nil || err2 != nil {
		t.Fatalf("failed to tls.Marshal() test data for get-entries: %v %v", err1, err2)
	}

	var tests = []struct {
		descr         string
		req           string
		want          int
		wantQuotaUser string
		glbrr         *trillian.GetLeavesByRangeRequest
		leaves        []*trillian.LogLeaf
		rpcErr        error
		slr           *trillian.SignedLogRoot
		errStr        string
	}{
		{
			descr: "invalid &&s",
			req:   "start=&&&&&&&&&end=wibble",
			want:  http.StatusBadRequest,
		},
		{
			descr: "start non numeric",
			req:   "start=fish&end=3",
			want:  http.StatusBadRequest,
		},
		{
			descr: "end non numeric",
			req:   "start=10&end=wibble",
			want:  http.StatusBadRequest,
		},
		{
			descr: "both non numeric",
			req:   "start=fish&end=wibble",
			want:  http.StatusBadRequest,
		},
		{
			descr: "end missing",
			req:   "start=1",
			want:  http.StatusBadRequest,
		},
		{
			descr: "start missing",
			req:   "end=1",
			want:  http.StatusBadRequest,
		},
		{
			descr: "both missing",
			req:   "",
			want:  http.StatusBadRequest,
		},
		{
			descr:  "backend rpc error",
			req:    "start=1&end=2",
			want:   http.StatusInternalServerError,
			rpcErr: errors.New("bang"),
			errStr: "bang",
		},
		{
			descr: "invalid log root",
			req:   "start=2&end=3",
			slr: &trillian.SignedLogRoot{
				LogRoot: []byte("not tls encoded data"),
			},
			glbrr:  &trillian.GetLeavesByRangeRequest{LogId: 0x42, StartIndex: 2, Count: 2},
			want:   http.StatusInternalServerError,
			leaves: []*trillian.LogLeaf{{LeafIndex: 2}, {LeafIndex: 3}},
			errStr: "failed to unmarshal",
		},
		{
			descr: "start outside tree size",
			req:   "start=2&end=3",
			slr: mustMarshalRoot(t, &types.LogRootV1{
				TreeSize: 2, // Not large enough - only indices 0 and 1 valid.
			}),
			glbrr:  &trillian.GetLeavesByRangeRequest{LogId: 0x42, StartIndex: 2, Count: 2},
			want:   http.StatusBadRequest,
			leaves: []*trillian.LogLeaf{{LeafIndex: 2}, {LeafIndex: 3}},
			errStr: "need tree size: 3 to get leaves but only got: 2",
		},
		{
			descr: "backend extra leaves",
			req:   "start=1&end=2",
			slr: mustMarshalRoot(t, &types.LogRootV1{
				TreeSize: 2,
			}),
			want:   http.StatusInternalServerError,
			leaves: []*trillian.LogLeaf{{LeafIndex: 1}, {LeafIndex: 2}, {LeafIndex: 3}},
			errStr: "too many leaves",
		},
		{
			descr:  "backend non-contiguous range",
			req:    "start=1&end=2",
			slr:    mustMarshalRoot(t, &types.LogRootV1{TreeSize: 100}),
			want:   http.StatusInternalServerError,
			leaves: []*trillian.LogLeaf{{LeafIndex: 1}, {LeafIndex: 3}},
			errStr: "unexpected leaf index",
		},
		{
			descr: "backend leaf corrupt",
			req:   "start=1&end=2",
			slr:   mustMarshalRoot(t, &types.LogRootV1{TreeSize: 100}),
			want:  http.StatusOK,
			leaves: []*trillian.LogLeaf{
				{LeafIndex: 1, MerkleLeafHash: []byte("hash"), LeafValue: []byte("NOT A MERKLE TREE LEAF")},
				{LeafIndex: 2, MerkleLeafHash: []byte("hash"), LeafValue: []byte("NOT A MERKLE TREE LEAF")},
			},
		},
		{
			descr: "leaves ok",
			req:   "start=1&end=2",
			slr:   mustMarshalRoot(t, &types.LogRootV1{TreeSize: 100}),
			want:  http.StatusOK,
			leaves: []*trillian.LogLeaf{
				{LeafIndex: 1, MerkleLeafHash: []byte("hash"), LeafValue: merkleBytes1, ExtraData: []byte("extra1")},
				{LeafIndex: 2, MerkleLeafHash: []byte("hash"), LeafValue: merkleBytes2, ExtraData: []byte("extra2")},
			},
		},
		{
			descr:         "leaves ok with quota",
			req:           "start=1&end=2",
			slr:           mustMarshalRoot(t, &types.LogRootV1{TreeSize: 100}),
			want:          http.StatusOK,
			wantQuotaUser: remoteQuotaUser,
			leaves: []*trillian.LogLeaf{
				{LeafIndex: 1, MerkleLeafHash: []byte("hash"), LeafValue: merkleBytes1, ExtraData: []byte("extra1")},
				{LeafIndex: 2, MerkleLeafHash: []byte("hash"), LeafValue: merkleBytes2, ExtraData: []byte("extra2")},
			},
		},
		{
			descr: "tree too small",
			req:   "start=5&end=6",
			glbrr: &trillian.GetLeavesByRangeRequest{LogId: 0x42, StartIndex: 5, Count: 2},
			want:  http.StatusBadRequest,
			slr: mustMarshalRoot(t, &types.LogRootV1{
				TreeSize: 5,
			}),
			leaves: []*trillian.LogLeaf{},
		},
		{
			descr: "tree includes 1 of 2",
			req:   "start=5&end=6",
			glbrr: &trillian.GetLeavesByRangeRequest{LogId: 0x42, StartIndex: 5, Count: 2},
			want:  http.StatusOK,
			slr: mustMarshalRoot(t, &types.LogRootV1{
				TreeSize: 6,
			}),
			leaves: []*trillian.LogLeaf{
				{LeafIndex: 5, MerkleLeafHash: []byte("hash5"), LeafValue: merkleBytes1, ExtraData: []byte("extra5")},
			},
		},
		{
			descr: "tree includes 2 of 2",
			req:   "start=5&end=6",
			glbrr: &trillian.GetLeavesByRangeRequest{LogId: 0x42, StartIndex: 5, Count: 2},
			want:  http.StatusOK,
			slr: mustMarshalRoot(t, &types.LogRootV1{
				TreeSize: 7,
			}),
			leaves: []*trillian.LogLeaf{
				{LeafIndex: 5, MerkleLeafHash: []byte("hash5"), LeafValue: merkleBytes1, ExtraData: []byte("extra5")},
				{LeafIndex: 6, MerkleLeafHash: []byte("hash6"), LeafValue: merkleBytes1, ExtraData: []byte("extra6")},
			},
		},
	}

	for _, test := range tests {
		info := setupTest(t, nil, nil)
		info.setRemoteQuotaUser(test.wantQuotaUser)
		handler := AppHandler{Info: info.li, Handler: getEntries, Name: "GetEntries", Method: http.MethodGet}
		path := fmt.Sprintf("/ct/v1/get-entries?%s", test.req)
		req, err := http.NewRequest(http.MethodGet, path, nil)
		if err != nil {
			t.Errorf("Failed to create request: %v", err)
			continue
		}
		slr := test.slr
		if slr == nil {
			slr = mustMarshalRoot(t, &types.LogRootV1{})
		}
		if test.leaves != nil || test.rpcErr != nil {
			var chargeTo *trillian.ChargeTo
			if len(test.wantQuotaUser) != 0 {
				chargeTo = &trillian.ChargeTo{User: []string{test.wantQuotaUser}}
			}
			glbrr := &trillian.GetLeavesByRangeRequest{LogId: 0x42, StartIndex: 1, Count: 2, ChargeTo: chargeTo}
			if test.glbrr != nil {
				glbrr = test.glbrr
			}
			rsp := trillian.GetLeavesByRangeResponse{SignedLogRoot: slr, Leaves: test.leaves}
			info.client.EXPECT().GetLeavesByRange(deadlineMatcher(), cmpMatcher{glbrr}).Return(&rsp, test.rpcErr)
		}

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if got := w.Code; got != test.want {
			t.Errorf("GetEntries(%q)=%d; want %d (because %s)", test.req, got, test.want, test.descr)
		}
		if test.errStr != "" {
			if body := w.Body.String(); !strings.Contains(body, test.errStr) {
				t.Errorf("GetEntries(%q)=%q; want to find %q (because %s)", test.req, body, test.errStr, test.descr)
			}
			continue
		}
		if test.want != http.StatusOK {
			continue
		}
		if got, want := w.Header().Get("Cache-Control"), "public"; !strings.Contains(got, want) {
			t.Errorf("GetEntries(%q): Cache-Control response header = %q, want %q", test.req, got, want)
		}
		// Leaf data should be passed through as-is even if invalid.
		var jsonMap map[string][]ct.LeafEntry
		if err := json.Unmarshal(w.Body.Bytes(), &jsonMap); err != nil {
			t.Errorf("Failed to unmarshal json response %s: %v", w.Body.Bytes(), err)
			continue
		}
		if got := len(jsonMap); got != 1 {
			t.Errorf("len(rspMap)=%d; want 1", got)
		}
		entries := jsonMap["entries"]
		if got, want := len(entries), len(test.leaves); got != want {
			t.Errorf("len(rspMap['entries']=%d; want %d", got, want)
			continue
		}
		for i := 0; i < len(entries); i++ {
			if got, want := string(entries[i].LeafInput), string(test.leaves[i].LeafValue); got != want {
				t.Errorf("rspMap['entries'][%d].LeafInput=%s; want %s", i, got, want)
			}
			if got, want := string(entries[i].ExtraData), string(test.leaves[i].ExtraData); got != want {
				t.Errorf("rspMap['entries'][%d].ExtraData=%s; want %s", i, got, want)
			}
		}

		info.mockCtrl.Finish()
	}
}

func TestGetEntriesRanges(t *testing.T) {
	var tests = []struct {
		desc          string
		start         int64
		end           int64
		rpcEnd        int64 // same as end if zero
		want          int
		wantQuotaUser string
		rpc           bool
	}{
		{
			desc:  "-ve start value not allowed",
			start: -1,
			end:   0,
			want:  http.StatusBadRequest,
		},
		{
			desc:  "-ve end value not allowed",
			start: 0,
			end:   -1,
			want:  http.StatusBadRequest,
		},
		{
			desc:  "invalid range end>start",
			start: 20,
			end:   10,
			want:  http.StatusBadRequest,
		},
		{
			desc:  "invalid range, -ve end",
			start: 3000,
			end:   -50,
			want:  http.StatusBadRequest,
		},
		{
			desc:  "valid range",
			start: 10,
			end:   20,
			want:  http.StatusInternalServerError,
			rpc:   true,
		},
		{
			desc:          "valid range quota",
			start:         10,
			end:           20,
			want:          http.StatusInternalServerError,
			wantQuotaUser: remoteQuotaUser,
			rpc:           true,
		},
		{
			desc:  "valid range, one entry",
			start: 10,
			end:   10,
			want:  http.StatusInternalServerError,
			rpc:   true,
		},
		{
			desc:  "invalid range, edge case",
			start: 10,
			end:   9,
			want:  http.StatusBadRequest,
		},
		{
			desc:   "range too large, coerced into alignment",
			start:  14,
			end:    50000,
			want:   http.StatusInternalServerError,
			rpcEnd: MaxGetEntriesAllowed - 1,
			rpc:    true,
		},
		{
			desc:   "range too large, already in alignment",
			start:  MaxGetEntriesAllowed,
			end:    5000,
			want:   http.StatusInternalServerError,
			rpcEnd: MaxGetEntriesAllowed + MaxGetEntriesAllowed - 1,
			rpc:    true,
		},
		{
			desc:   "small range straddling boundary, not coerced",
			start:  MaxGetEntriesAllowed - 2,
			end:    MaxGetEntriesAllowed + 2,
			want:   http.StatusInternalServerError,
			rpcEnd: MaxGetEntriesAllowed + 2,
			rpc:    true,
		},
	}

	// This tests that only valid ranges make it to the backend for get-entries.
	// We're testing request handling up to the point where we make the RPC so arrange for
	// it to fail with a specific error.
	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			info := setupTest(t, nil, nil)
			defer info.mockCtrl.Finish()
			handler := AppHandler{Info: info.li, Handler: getEntries, Name: "GetEntries", Method: http.MethodGet}

			info.setRemoteQuotaUser(test.wantQuotaUser)
			if test.rpc {
				end := test.rpcEnd
				if end == 0 {
					end = test.end
				}
				var chargeTo *trillian.ChargeTo
				if len(test.wantQuotaUser) != 0 {
					chargeTo = &trillian.ChargeTo{User: []string{test.wantQuotaUser}}
				}
				info.client.EXPECT().GetLeavesByRange(deadlineMatcher(), cmpMatcher{&trillian.GetLeavesByRangeRequest{LogId: 0x42, StartIndex: test.start, Count: end + 1 - test.start, ChargeTo: chargeTo}}).Return(nil, errors.New("RPCMADE"))
			}

			path := fmt.Sprintf("/ct/v1/get-entries?start=%d&end=%d", test.start, test.end)
			req, err := http.NewRequest(http.MethodGet, path, nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if got := w.Code; got != test.want {
				t.Errorf("getEntries(%d, %d)=%d; want %d for test %s", test.start, test.end, got, test.want, test.desc)
			}
			if test.rpc && !strings.Contains(w.Body.String(), "RPCMADE") {
				// If an RPC was emitted, it should have received and propagated an error.
				t.Errorf("getEntries(%d, %d)=%q; expect RPCMADE for test %s", test.start, test.end, w.Body, test.desc)
			}
		})
	}
}

func TestGetProofByHash(t *testing.T) {
	auditHashes := [][]byte{
		[]byte("abcdef78901234567890123456789012"),
		[]byte("ghijkl78901234567890123456789012"),
		[]byte("mnopqr78901234567890123456789012"),
	}
	inclusionProof := ct.GetProofByHashResponse{
		LeafIndex: 2,
		AuditPath: auditHashes,
	}

	var tests = []struct {
		req           string
		want          int
		wantQuotaUser string
		rpcRsp        *trillian.GetInclusionProofByHashResponse
		httpRsp       *ct.GetProofByHashResponse
		httpJSON      string
		rpcErr        error
		errStr        string
	}{
		{
			req:  "",
			want: http.StatusBadRequest,
		},
		{
			req:  "hash=&tree_size=1",
			want: http.StatusBadRequest,
		},
		{
			req:  "hash=''&tree_size=1",
			want: http.StatusBadRequest,
		},
		{
			req:  "hash=notbase64data&tree_size=1",
			want: http.StatusBadRequest,
		},
		{
			req:  "tree_size=-1&hash=aGkK",
			want: http.StatusBadRequest,
		},
		{
			req:    "tree_size=6&hash=YWhhc2g=",
			want:   http.StatusInternalServerError,
			rpcErr: errors.New("RPCFAIL"),
			errStr: "RPCFAIL",
		},
		{
			req:  "tree_size=11&hash=YWhhc2g=",
			want: http.StatusNotFound,
			rpcRsp: &trillian.GetInclusionProofByHashResponse{
				SignedLogRoot: mustMarshalRoot(t, &types.LogRootV1{
					TreeSize: 10, // Not large enough to handle the request.
				}),
				Proof: []*trillian.Proof{
					{
						LeafIndex: 0,
						Hashes:    nil,
					},
				},
			},
		},
		{
			req:  "tree_size=11&hash=YWhhc2g=",
			want: http.StatusInternalServerError,
			rpcRsp: &trillian.GetInclusionProofByHashResponse{
				SignedLogRoot: &trillian.SignedLogRoot{
					LogRoot: []byte("not tls encoded data"),
				},
			},
		},
		{
			req:  "tree_size=1&hash=YWhhc2g=",
			want: http.StatusOK,
			rpcRsp: &trillian.GetInclusionProofByHashResponse{
				SignedLogRoot: mustMarshalRoot(t, &types.LogRootV1{
					TreeSize: 10,
				}),
				Proof: []*trillian.Proof{
					{
						LeafIndex: 0,
						Hashes:    nil,
					},
				},
			},
			httpRsp: &ct.GetProofByHashResponse{LeafIndex: 0, AuditPath: nil},
			// Check undecoded JSON to confirm use of '[]' not 'null'
			httpJSON: "{\"leaf_index\":0,\"audit_path\":[]}",
		},
		{
			req:  "tree_size=1&hash=YWhhc2g=",
			want: http.StatusOK,
			// Want quota
			wantQuotaUser: remoteQuotaUser,
			rpcRsp: &trillian.GetInclusionProofByHashResponse{
				SignedLogRoot: mustMarshalRoot(t, &types.LogRootV1{
					TreeSize: 10,
				}),
				Proof: []*trillian.Proof{
					{
						LeafIndex: 0,
						Hashes:    nil,
					},
				},
			},
			httpRsp: &ct.GetProofByHashResponse{LeafIndex: 0, AuditPath: nil},
			// Check undecoded JSON to confirm use of '[]' not 'null'
			httpJSON: "{\"leaf_index\":0,\"audit_path\":[]}",
		},
		{
			req:  "tree_size=7&hash=YWhhc2g=",
			want: http.StatusOK,
			rpcRsp: &trillian.GetInclusionProofByHashResponse{
				SignedLogRoot: mustMarshalRoot(t, &types.LogRootV1{
					TreeSize: 10,
				}),
				Proof: []*trillian.Proof{
					{
						LeafIndex: 2,
						Hashes:    auditHashes,
					},
					// Second proof ignored.
					{
						LeafIndex: 2,
						Hashes:    [][]byte{[]byte("ghijkl")},
					},
				},
			},
			httpRsp: &inclusionProof,
		},
		{
			req:  "tree_size=9&hash=YWhhc2g=",
			want: http.StatusInternalServerError,
			rpcRsp: &trillian.GetInclusionProofByHashResponse{
				SignedLogRoot: mustMarshalRoot(t, &types.LogRootV1{
					TreeSize: 10,
				}),
				Proof: []*trillian.Proof{
					{
						LeafIndex: 2,
						Hashes: [][]byte{
							auditHashes[0],
							{}, // missing hash
							auditHashes[2],
						},
					},
				},
			},
			errStr: "invalid proof",
		},
		{
			req:  "tree_size=7&hash=YWhhc2g=",
			want: http.StatusOK,
			rpcRsp: &trillian.GetInclusionProofByHashResponse{
				SignedLogRoot: mustMarshalRoot(t, &types.LogRootV1{
					TreeSize: 10,
				}),
				Proof: []*trillian.Proof{
					{
						LeafIndex: 2,
						Hashes:    auditHashes,
					},
				},
			},
			httpRsp: &inclusionProof,
		},
		{
			// Hash with URL-encoded %2B -> '+'.
			req:  "hash=WtfX3Axbm7UwtY7GhHoAHPCtXJVrY5vZsH%2ByaXOD2GI=&tree_size=1",
			want: http.StatusOK,
			rpcRsp: &trillian.GetInclusionProofByHashResponse{
				SignedLogRoot: mustMarshalRoot(t, &types.LogRootV1{
					TreeSize: 10,
				}),
				Proof: []*trillian.Proof{
					{
						LeafIndex: 2,
						Hashes:    auditHashes,
					},
				},
			},
			httpRsp: &inclusionProof,
		},
		{
			req:  "tree_size=10&hash=YWhhc2g=",
			want: http.StatusNotFound,
			rpcRsp: &trillian.GetInclusionProofByHashResponse{
				SignedLogRoot: mustMarshalRoot(t, &types.LogRootV1{
					TreeSize: 5,
				}),
				Proof: []*trillian.Proof{
					{
						LeafIndex: 0,
						Hashes:    nil,
					},
				},
			},
		},
		{
			req:  "tree_size=10&hash=YWhhc2g=",
			want: http.StatusOK,
			rpcRsp: &trillian.GetInclusionProofByHashResponse{
				SignedLogRoot: mustMarshalRoot(t, &types.LogRootV1{
					// Returned tree large enough to include the leaf.
					TreeSize: 10,
				}),
				Proof: []*trillian.Proof{
					{
						LeafIndex: 2,
						Hashes:    auditHashes,
					},
				},
			},
			httpRsp: &inclusionProof,
		},
		{
			req:  "tree_size=10&hash=YWhhc2g=",
			want: http.StatusOK,
			rpcRsp: &trillian.GetInclusionProofByHashResponse{
				SignedLogRoot: mustMarshalRoot(t, &types.LogRootV1{
					// Returned tree larger than needed to include the leaf.
					TreeSize: 20,
				}),
				Proof: []*trillian.Proof{
					{
						LeafIndex: 2,
						Hashes:    auditHashes,
					},
				},
			},
			httpRsp: &inclusionProof,
		},
	}
	info := setupTest(t, nil, nil)
	defer info.mockCtrl.Finish()
	handler := AppHandler{Info: info.li, Handler: getProofByHash, Name: "GetProofByHash", Method: http.MethodGet}

	for _, test := range tests {
		info.setRemoteQuotaUser(test.wantQuotaUser)
		req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("/ct/v1/proof-by-hash?%s", test.req), nil)
		if err != nil {
			t.Errorf("Failed to create request: %v", err)
			continue
		}
		if test.rpcRsp != nil || test.rpcErr != nil {
			info.client.EXPECT().GetInclusionProofByHash(deadlineMatcher(), gomock.Any()).Return(test.rpcRsp, test.rpcErr)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if got := w.Code; got != test.want {
			t.Errorf("proofByHash(%s)=%d; want %d", test.req, got, test.want)
		}
		if test.errStr != "" {
			if body := w.Body.String(); !strings.Contains(body, test.errStr) {
				t.Errorf("proofByHash(%q)=%q; want to find %q", test.req, body, test.errStr)
			}
			continue
		}
		if test.want != http.StatusOK {
			continue
		}
		if got, want := w.Header().Get("Cache-Control"), "public"; !strings.Contains(got, want) {
			t.Errorf("proofByHash(%q): Cache-Control response header = %q, want %q", test.req, got, want)
		}
		jsonData, err := io.ReadAll(w.Body)
		if err != nil {
			t.Errorf("failed to read response body: %v", err)
			continue
		}
		var resp ct.GetProofByHashResponse
		if err = json.Unmarshal(jsonData, &resp); err != nil {
			t.Errorf("Failed to unmarshal json response %s: %v", jsonData, err)
			continue
		}
		if diff := pretty.Compare(resp, test.httpRsp); diff != "" {
			t.Errorf("proofByHash(%q) diff:\n%v", test.req, diff)
		}
		if test.httpJSON != "" {
			// Also check the JSON string is as expected
			if diff := pretty.Compare(string(jsonData), test.httpJSON); diff != "" {
				t.Errorf("proofByHash(%q) diff:\n%v", test.req, diff)
			}
		}
	}
}

func TestGetSTHConsistency(t *testing.T) {
	auditHashes := [][]byte{
		[]byte("abcdef78901234567890123456789012"),
		[]byte("ghijkl78901234567890123456789012"),
		[]byte("mnopqr78901234567890123456789012"),
	}
	var tests = []struct {
		req           string
		want          int
		wantQuotaUser string
		first, second int64
		rpcRsp        *trillian.GetConsistencyProofResponse
		httpRsp       *ct.GetSTHConsistencyResponse
		httpJSON      string
		rpcErr        error
		errStr        string
	}{
		{
			req:    "",
			want:   http.StatusBadRequest,
			errStr: "parameter 'first' is required",
		},
		{
			req:    "first=apple&second=orange",
			want:   http.StatusBadRequest,
			errStr: "parameter 'first' is malformed",
		},
		{
			req:    "first=1&last=2",
			want:   http.StatusBadRequest,
			errStr: "parameter 'second' is required",
		},
		{
			req:    "first=1&second=a",
			want:   http.StatusBadRequest,
			errStr: "parameter 'second' is malformed",
		},
		{
			req:    "first=a&second=2",
			want:   http.StatusBadRequest,
			errStr: "parameter 'first' is malformed",
		},
		{
			req:    "first=-1&second=10",
			want:   http.StatusBadRequest,
			errStr: "first and second params cannot be <0: -1 10",
		},
		{
			req:    "first=10&second=-11",
			want:   http.StatusBadRequest,
			errStr: "first and second params cannot be <0: 10 -11",
		},
		{
			req:  "first=0&second=1",
			want: http.StatusOK,
			httpRsp: &ct.GetSTHConsistencyResponse{
				Consistency: nil,
			},
			// Check a nil proof is passed through as '[]' not 'null' in raw JSON.
			httpJSON: "{\"consistency\":[]}",
		},
		{
			req:  "first=0&second=1",
			want: http.StatusOK,
			// Want quota
			wantQuotaUser: remoteQuotaUser,
			httpRsp: &ct.GetSTHConsistencyResponse{
				Consistency: nil,
			},
			// Check a nil proof is passed through as '[]' not 'null' in raw JSON.
			httpJSON: "{\"consistency\":[]}",
		},
		{
			// Check that unrecognized parameters are ignored.
			req:     "first=0&second=1&third=2&fourth=3",
			want:    http.StatusOK,
			httpRsp: &ct.GetSTHConsistencyResponse{},
		},
		{
			req:    "first=998&second=997",
			want:   http.StatusBadRequest,
			errStr: "invalid first, second params: 998 997",
		},
		{
			req:    "first=1000&second=200",
			want:   http.StatusBadRequest,
			errStr: "invalid first, second params: 1000 200",
		},
		{
			req:    "first=10",
			want:   http.StatusBadRequest,
			errStr: "parameter 'second' is required",
		},
		{
			req:    "second=20",
			want:   http.StatusBadRequest,
			errStr: "parameter 'first' is required",
		},
		{
			req:    "first=10&second=20",
			first:  10,
			second: 20,
			want:   http.StatusInternalServerError,
			rpcErr: errors.New("RPCFAIL"),
			errStr: "RPCFAIL",
		},
		{
			req:    "first=10&second=20",
			first:  10,
			second: 20,
			want:   http.StatusInternalServerError,
			rpcRsp: &trillian.GetConsistencyProofResponse{
				SignedLogRoot: mustMarshalRoot(t, &types.LogRootV1{
					TreeSize: 50,
				}),
				Proof: &trillian.Proof{
					LeafIndex: 2,
					Hashes: [][]byte{
						auditHashes[0],
						{}, // missing hash
						auditHashes[2],
					},
				},
			},
			errStr: "invalid proof",
		},
		{
			req:    "first=10&second=20",
			first:  10,
			second: 20,
			want:   http.StatusInternalServerError,
			rpcRsp: &trillian.GetConsistencyProofResponse{
				SignedLogRoot: &trillian.SignedLogRoot{
					LogRoot: []byte("not tls encoded data"),
				},
			},
			errStr: "failed to unmarshal",
		},
		{
			req:    "first=10&second=20",
			first:  10,
			second: 20,
			want:   http.StatusBadRequest,
			rpcRsp: &trillian.GetConsistencyProofResponse{
				SignedLogRoot: mustMarshalRoot(t, &types.LogRootV1{
					TreeSize: 19, // Tree not large enough to serve the request.
				}),
				Proof: &trillian.Proof{
					LeafIndex: 2,
					Hashes: [][]byte{
						auditHashes[0],
						{}, // missing hash
						auditHashes[2],
					},
				},
			},
			errStr: "need tree size: 20",
		},
		{
			req:    "first=10&second=20",
			first:  10,
			second: 20,
			want:   http.StatusInternalServerError,
			rpcRsp: &trillian.GetConsistencyProofResponse{
				SignedLogRoot: mustMarshalRoot(t, &types.LogRootV1{
					TreeSize: 50,
				}),
				Proof: &trillian.Proof{
					LeafIndex: 2,
					Hashes: [][]byte{
						auditHashes[0],
						auditHashes[1][:30], // wrong size hash
						auditHashes[2],
					},
				},
			},
			errStr: "invalid proof",
		},
		{
			req:    "first=10&second=20",
			first:  10,
			second: 20,
			want:   http.StatusOK,
			rpcRsp: &trillian.GetConsistencyProofResponse{
				SignedLogRoot: mustMarshalRoot(t, &types.LogRootV1{
					TreeSize: 50,
				}),
				Proof: &trillian.Proof{
					LeafIndex: 2,
					Hashes:    auditHashes,
				},
			},
			httpRsp: &ct.GetSTHConsistencyResponse{
				Consistency: auditHashes,
			},
		},
		{
			req:    "first=1&second=2",
			first:  1,
			second: 2,
			want:   http.StatusOK,
			rpcRsp: &trillian.GetConsistencyProofResponse{
				SignedLogRoot: mustMarshalRoot(t, &types.LogRootV1{
					TreeSize: 50,
				}),
				Proof: &trillian.Proof{
					LeafIndex: 0,
					Hashes:    nil,
				},
			},
			httpRsp: &ct.GetSTHConsistencyResponse{
				Consistency: nil,
			},
			// Check a nil proof is passed through as '[]' not 'null' in raw JSON.
			httpJSON: "{\"consistency\":[]}",
		},
		{
			req:    "first=332&second=332",
			first:  332,
			second: 332,
			want:   http.StatusOK,
			rpcRsp: &trillian.GetConsistencyProofResponse{
				SignedLogRoot: mustMarshalRoot(t, &types.LogRootV1{
					TreeSize: 333,
				}),
				Proof: &trillian.Proof{
					LeafIndex: 0,
					Hashes:    nil,
				},
			},
			httpRsp: &ct.GetSTHConsistencyResponse{
				Consistency: nil,
			},
			// Check a nil proof is passed through as '[]' not 'null' in raw JSON.
			httpJSON: "{\"consistency\":[]}",
		},
		{
			req:    "first=332&second=332",
			first:  332,
			second: 332,
			want:   http.StatusBadRequest,
			rpcRsp: &trillian.GetConsistencyProofResponse{
				SignedLogRoot: mustMarshalRoot(t, &types.LogRootV1{
					// Backend returns a tree size too small to satisfy the proof.
					TreeSize: 331,
				}),
				Proof: &trillian.Proof{
					Hashes: nil,
				},
			},
		},
		{
			req:    "first=332&second=332",
			first:  332,
			second: 332,
			want:   http.StatusOK,
			rpcRsp: &trillian.GetConsistencyProofResponse{
				SignedLogRoot: mustMarshalRoot(t, &types.LogRootV1{
					// Backend returns a tree size just large enough to satisfy the proof.
					TreeSize: 332,
				}),
				Proof: &trillian.Proof{
					LeafIndex: 2,
					Hashes:    auditHashes,
				},
			},
			httpRsp: &ct.GetSTHConsistencyResponse{
				Consistency: auditHashes,
			},
		},
		{
			req:    "first=332&second=332",
			first:  332,
			second: 332,
			want:   http.StatusOK,
			rpcRsp: &trillian.GetConsistencyProofResponse{
				SignedLogRoot: mustMarshalRoot(t, &types.LogRootV1{
					// Backend returns a tree size larger than needed to satisfy the proof.
					TreeSize: 333,
				}),
				Proof: &trillian.Proof{
					LeafIndex: 2,
					Hashes:    auditHashes,
				},
			},
			httpRsp: &ct.GetSTHConsistencyResponse{
				Consistency: auditHashes,
			},
		},
		{
			req:  "first=332&second=331",
			want: http.StatusBadRequest,
		},
	}

	info := setupTest(t, nil, nil)
	defer info.mockCtrl.Finish()
	handler := AppHandler{Info: info.li, Handler: getSTHConsistency, Name: "GetSTHConsistency", Method: http.MethodGet}

	for _, test := range tests {
		info.setRemoteQuotaUser(test.wantQuotaUser)
		req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("/ct/v1/get-sth-consistency?%s", test.req), nil)
		if err != nil {
			t.Errorf("Failed to create request: %v", err)
			continue
		}
		if test.rpcRsp != nil || test.rpcErr != nil {
			req := trillian.GetConsistencyProofRequest{
				LogId:          0x42,
				FirstTreeSize:  test.first,
				SecondTreeSize: test.second,
			}
			if len(test.wantQuotaUser) > 0 {
				req.ChargeTo = &trillian.ChargeTo{User: []string{test.wantQuotaUser}}
			}
			info.client.EXPECT().GetConsistencyProof(deadlineMatcher(), cmpMatcher{&req}).Return(test.rpcRsp, test.rpcErr)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if got := w.Code; got != test.want {
			t.Errorf("getSTHConsistency(%s)=%d; want %d", test.req, got, test.want)
		}
		if test.errStr != "" {
			if body := w.Body.String(); !strings.Contains(body, test.errStr) {
				t.Errorf("getSTHConsistency(%q)=%q; want to find %q", test.req, body, test.errStr)
			}
			continue
		}
		if test.want != http.StatusOK {
			continue
		}
		if got, want := w.Header().Get("Cache-Control"), "public"; !strings.Contains(got, want) {
			t.Errorf("getSTHConsistency(%q): Cache-Control response header = %q, want %q", test.req, got, want)
		}
		jsonData, err := io.ReadAll(w.Body)
		if err != nil {
			t.Errorf("failed to read response body: %v", err)
			continue
		}
		var resp ct.GetSTHConsistencyResponse
		if err = json.Unmarshal(jsonData, &resp); err != nil {
			t.Errorf("Failed to unmarshal json response %s: %v", jsonData, err)
			continue
		}
		if diff := pretty.Compare(resp, test.httpRsp); diff != "" {
			t.Errorf("getSTHConsistency(%q) diff:\n%v", test.req, diff)
		}
		if test.httpJSON != "" {
			// Also check the JSON string is as expected
			if diff := pretty.Compare(string(jsonData), test.httpJSON); diff != "" {
				t.Errorf("getSTHConsistency(%q) diff:\n%v", test.req, diff)
			}
		}
	}
}

func TestGetEntryAndProof(t *testing.T) {
	merkleLeaf := ct.MerkleTreeLeaf{
		Version:  ct.V1,
		LeafType: ct.TimestampedEntryLeafType,
		TimestampedEntry: &ct.TimestampedEntry{
			Timestamp:  12345,
			EntryType:  ct.X509LogEntryType,
			X509Entry:  &ct.ASN1Cert{Data: []byte("certdatacertdata")},
			Extensions: ct.CTExtensions{},
		},
	}
	leafBytes, err := tls.Marshal(merkleLeaf)
	if err != nil {
		t.Fatalf("failed to build test Merkle leaf data: %v", err)
	}
	proofRsp := ct.GetEntryAndProofResponse{
		LeafInput: leafBytes,
		ExtraData: []byte("extra"),
		AuditPath: [][]byte{[]byte("abcdef"), []byte("ghijkl"), []byte("mnopqr")},
	}

	var tests = []struct {
		req           string
		idx, sz       int64
		want          int
		wantQuotaUser string
		wantRsp       *ct.GetEntryAndProofResponse
		rpcRsp        *trillian.GetEntryAndProofResponse
		rpcErr        error
		errStr        string
	}{
		{
			req:  "",
			want: http.StatusBadRequest,
		},
		{
			req:  "leaf_index=b",
			want: http.StatusBadRequest,
		},
		{
			req:  "leaf_index=1&tree_size=-1",
			want: http.StatusBadRequest,
		},
		{
			req:  "leaf_index=-1&tree_size=1",
			want: http.StatusBadRequest,
		},
		{
			req:  "leaf_index=1&tree_size=d",
			want: http.StatusBadRequest,
		},
		{
			req:  "leaf_index=&tree_size=",
			want: http.StatusBadRequest,
		},
		{
			req:  "leaf_index=",
			want: http.StatusBadRequest,
		},
		{
			req:  "leaf_index=1&tree_size=0",
			want: http.StatusBadRequest,
		},
		{
			req:  "leaf_index=10&tree_size=5",
			want: http.StatusBadRequest,
		},
		{
			req:  "leaf_index=tree_size",
			want: http.StatusBadRequest,
		},
		{
			req:    "leaf_index=1&tree_size=3",
			idx:    1,
			sz:     3,
			want:   http.StatusInternalServerError,
			rpcErr: errors.New("RPCFAIL"),
			errStr: "RPCFAIL",
		},
		{
			req:  "leaf_index=1&tree_size=3",
			idx:  1,
			sz:   3,
			want: http.StatusInternalServerError,
			// No result data in backend response
			rpcRsp: &trillian.GetEntryAndProofResponse{},
		},
		{
			req:     "leaf_index=1&tree_size=3",
			idx:     1,
			sz:      3,
			want:    http.StatusOK,
			wantRsp: &proofRsp,
			rpcRsp: &trillian.GetEntryAndProofResponse{
				SignedLogRoot: mustMarshalRoot(t, &types.LogRootV1{
					// Server returns a tree not large enough for the proof.
					TreeSize: 20,
				}),
				Proof: &trillian.Proof{
					LeafIndex: 2,
					Hashes: [][]byte{
						[]byte("abcdef"),
						[]byte("ghijkl"),
						[]byte("mnopqr"),
					},
				},
				// To match merkleLeaf above.
				Leaf: &trillian.LogLeaf{
					LeafValue:      leafBytes,
					MerkleLeafHash: []byte("ahash"),
					ExtraData:      []byte("extra"),
				},
			},
		},
		{
			req:     "leaf_index=1&tree_size=3",
			idx:     1,
			sz:      3,
			want:    http.StatusOK,
			wantRsp: &proofRsp,
			// wantQuota
			wantQuotaUser: remoteQuotaUser,
			rpcRsp: &trillian.GetEntryAndProofResponse{
				SignedLogRoot: mustMarshalRoot(t, &types.LogRootV1{
					// Server returns a tree not large enough for the proof.
					TreeSize: 20,
				}),
				Proof: &trillian.Proof{
					LeafIndex: 2,
					Hashes: [][]byte{
						[]byte("abcdef"),
						[]byte("ghijkl"),
						[]byte("mnopqr"),
					},
				},
				// To match merkleLeaf above.
				Leaf: &trillian.LogLeaf{
					LeafValue:      leafBytes,
					MerkleLeafHash: []byte("ahash"),
					ExtraData:      []byte("extra"),
				},
			},
		},
		{
			req:  "leaf_index=1&tree_size=3",
			idx:  1,
			sz:   3,
			want: http.StatusBadRequest,
			rpcRsp: &trillian.GetEntryAndProofResponse{
				SignedLogRoot: mustMarshalRoot(t, &types.LogRootV1{
					// Server returns a tree not large enough for the proof.
					TreeSize: 2,
				}),
				Proof: &trillian.Proof{},
			},
		},
		{
			req:     "leaf_index=1&tree_size=3",
			idx:     1,
			sz:      3,
			want:    http.StatusOK,
			wantRsp: &proofRsp,
			rpcRsp: &trillian.GetEntryAndProofResponse{
				SignedLogRoot: mustMarshalRoot(t, &types.LogRootV1{
					// Server returns a tree just large enough for the proof.
					TreeSize: 3,
				}),
				Proof: &trillian.Proof{
					LeafIndex: 2,
					Hashes: [][]byte{
						[]byte("abcdef"),
						[]byte("ghijkl"),
						[]byte("mnopqr"),
					},
				},
				// To match merkleLeaf above.
				Leaf: &trillian.LogLeaf{
					LeafValue:      leafBytes,
					MerkleLeafHash: []byte("ahash"),
					ExtraData:      []byte("extra"),
				},
			},
		},
		{
			req:     "leaf_index=1&tree_size=3",
			idx:     1,
			sz:      3,
			want:    http.StatusOK,
			wantRsp: &proofRsp,
			rpcRsp: &trillian.GetEntryAndProofResponse{
				SignedLogRoot: mustMarshalRoot(t, &types.LogRootV1{
					// Server returns a tree larger than needed for the proof.
					TreeSize: 300,
				}),
				Proof: &trillian.Proof{
					LeafIndex: 2,
					Hashes: [][]byte{
						[]byte("abcdef"),
						[]byte("ghijkl"),
						[]byte("mnopqr"),
					},
				},
				// To match merkleLeaf above.
				Leaf: &trillian.LogLeaf{
					LeafValue:      leafBytes,
					MerkleLeafHash: []byte("ahash"),
					ExtraData:      []byte("extra"),
				},
			},
		},
		{
			req:  "leaf_index=0&tree_size=1",
			idx:  0,
			sz:   1,
			want: http.StatusOK,
			wantRsp: &ct.GetEntryAndProofResponse{
				LeafInput: leafBytes,
				ExtraData: []byte("extra"),
			},
			rpcRsp: &trillian.GetEntryAndProofResponse{
				SignedLogRoot: mustMarshalRoot(t, &types.LogRootV1{
					// Server returns a tree larger than needed for the proof.
					TreeSize: 300,
				}),
				Proof: &trillian.Proof{
					// Empty proof OK for requested tree size of 1.
					LeafIndex: 0,
				},
				// To match merkleLeaf above.
				Leaf: &trillian.LogLeaf{
					LeafValue:      leafBytes,
					MerkleLeafHash: []byte("ahash"),
					ExtraData:      []byte("extra"),
				},
			},
		},
		{
			req:  "leaf_index=0&tree_size=1",
			idx:  0,
			sz:   1,
			want: http.StatusInternalServerError,
			rpcRsp: &trillian.GetEntryAndProofResponse{
				SignedLogRoot: mustMarshalRoot(t, &types.LogRootV1{
					// Server returns a tree larger than needed for the proof.
					TreeSize: 300,
				}),
				// No proof.
				Leaf: &trillian.LogLeaf{
					LeafValue:      leafBytes,
					MerkleLeafHash: []byte("ahash"),
					ExtraData:      []byte("extra"),
				},
			},
		},
		{
			req:  "leaf_index=0&tree_size=1",
			idx:  0,
			sz:   1,
			want: http.StatusInternalServerError,
			rpcRsp: &trillian.GetEntryAndProofResponse{
				SignedLogRoot: mustMarshalRoot(t, &types.LogRootV1{
					// Server returns a tree larger than needed for the proof.
					TreeSize: 300,
				}),
				Proof: &trillian.Proof{
					// Empty proof OK for requested tree size of 1.
					LeafIndex: 0,
				},
				// No leaf.
			},
		},
	}

	info := setupTest(t, nil, nil)
	defer info.mockCtrl.Finish()
	handler := AppHandler{Info: info.li, Handler: getEntryAndProof, Name: "GetEntryAndProof", Method: http.MethodGet}

	for _, test := range tests {
		info.setRemoteQuotaUser(test.wantQuotaUser)
		req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("/ct/v1/get-entry-and-proof?%s", test.req), nil)
		if err != nil {
			t.Errorf("Failed to create request: %v", err)
			continue
		}

		if test.rpcRsp != nil || test.rpcErr != nil {
			req := &trillian.GetEntryAndProofRequest{LogId: 0x42, LeafIndex: test.idx, TreeSize: test.sz}
			if len(test.wantQuotaUser) > 0 {
				req.ChargeTo = &trillian.ChargeTo{User: []string{test.wantQuotaUser}}
			}
			info.client.EXPECT().GetEntryAndProof(deadlineMatcher(), cmpMatcher{req}).Return(test.rpcRsp, test.rpcErr)
		}

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if got := w.Code; got != test.want {
			t.Errorf("getEntryAndProof(%s)=%d; want %d", test.req, got, test.want)
		}
		if test.errStr != "" {
			if body := w.Body.String(); !strings.Contains(body, test.errStr) {
				t.Errorf("getEntryAndProof(%q)=%q; want to find %q", test.req, body, test.errStr)
			}
			continue
		}
		if test.want != http.StatusOK {
			continue
		}

		if got, want := w.Header().Get("Cache-Control"), "public"; !strings.Contains(got, want) {
			t.Errorf("getEntryAndProof(%q): Cache-Control response header = %q, want %q", test.req, got, want)
		}

		var resp ct.GetEntryAndProofResponse
		if err = json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Errorf("Failed to unmarshal json response %s: %v", w.Body.Bytes(), err)
			continue
		}
		// The result we expect after a roundtrip in the successful get entry and proof test
		if diff := pretty.Compare(&resp, test.wantRsp); diff != "" {
			t.Errorf("getEntryAndProof(%q) diff:\n%v", test.req, diff)
		}
	}
}

func TestGetLogV3JSON(t *testing.T) {
	info := setupTest(t, nil, nil)
	defer info.mockCtrl.Finish()
	info.li.instanceOpts.Validated.Config.Logv3Url = "http://example.com"
	handler := AppHandler{Info: info.li, Handler: logV3JSON, Name: "LogV3JSON", Method: http.MethodGet}

	req, err := http.NewRequest(http.MethodGet, "http://example.com/log.v3.json", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if got, want := w.Code, http.StatusOK; got != want {
		t.Fatalf("http.Get(logV3JSON)=%d; want %d", got, want)
	}

	var parsedJSON map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &parsedJSON); err != nil {
		t.Fatalf("json.Unmarshal(%q)=%q; want nil", w.Body.Bytes(), err)
	}
	if got := len(parsedJSON); got < 4 {
		t.Errorf("len(json)=%d; want >=4", got)
	}
}

func createJSONChain(t *testing.T, p x509util.PEMCertPool) io.Reader {
	t.Helper()
	var req ct.AddChainRequest
	for _, rawCert := range p.RawCertificates() {
		req.Chain = append(req.Chain, rawCert.Raw)
	}

	var buffer bytes.Buffer
	// It's tempting to avoid creating and flushing the intermediate writer but it doesn't work
	writer := bufio.NewWriter(&buffer)
	err := json.NewEncoder(writer).Encode(&req)
	if err := writer.Flush(); err != nil {
		t.Error(err)
	}

	if err != nil {
		t.Fatalf("Failed to create test json: %v", err)
	}

	return bufio.NewReader(&buffer)
}

func logLeafForCert(t *testing.T, certs []*x509.Certificate, merkleLeaf *ct.MerkleTreeLeaf, isPrecert bool) *trillian.LogLeaf {
	t.Helper()
	leafData, err := tls.Marshal(*merkleLeaf)
	if err != nil {
		t.Fatalf("failed to serialize leaf: %v", err)
	}

	raw := extractRawCerts(certs)
	leafIDHash := sha256.Sum256(raw[0].Data)

	extraData, err := util.ExtraDataForChain(raw[0], raw[1:], isPrecert)
	if err != nil {
		t.Fatalf("failed to serialize extra data: %v", err)
	}

	return &trillian.LogLeaf{LeafIdentityHash: leafIDHash[:], LeafValue: leafData, ExtraData: extraData}
}

type dlMatcher struct {
}

func deadlineMatcher() gomock.Matcher {
	return dlMatcher{}
}

func (d dlMatcher) Matches(x interface{}) bool {
	ctx, ok := x.(context.Context)
	if !ok {
		return false
	}

	deadlineTime, ok := ctx.Deadline()
	if !ok {
		return false // we never make RPC calls without a deadline set
	}

	return deadlineTime.Equal(fakeDeadlineTime)
}

func (d dlMatcher) String() string {
	return fmt.Sprintf("deadline is %v", fakeDeadlineTime)
}

func makeAddPrechainRequest(t *testing.T, li *logInfo, body io.Reader) *httptest.ResponseRecorder {
	t.Helper()
	handler := AppHandler{Info: li, Handler: addPreChain, Name: "AddPreChain", Method: http.MethodPost}
	return makeAddChainRequestInternal(t, handler, "add-pre-chain", body)
}

func makeAddChainRequest(t *testing.T, li *logInfo, body io.Reader) *httptest.ResponseRecorder {
	t.Helper()
	handler := AppHandler{Info: li, Handler: addChain, Name: "AddChain", Method: http.MethodPost}
	return makeAddChainRequestInternal(t, handler, "add-chain", body)
}

func makeAddChainRequestInternal(t *testing.T, handler AppHandler, path string, body io.Reader) *httptest.ResponseRecorder {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("http://example.com/ct/v1/%s", path), body)
	if err != nil {
		t.Fatalf("Failed to create POST request: %v", err)
	}

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	return w
}

func makeGetRootResponseForTest(t *testing.T, stamp, treeSize int64, hash []byte) *trillian.GetLatestSignedLogRootResponse {
	t.Helper()
	return &trillian.GetLatestSignedLogRootResponse{
		SignedLogRoot: mustMarshalRoot(t, &types.LogRootV1{
			TimestampNanos: uint64(stamp),
			TreeSize:       uint64(treeSize),
			RootHash:       hash,
		}),
	}
}

func loadCertsIntoPoolOrDie(t *testing.T, certs []string) *x509util.PEMCertPool {
	t.Helper()
	pool := x509util.NewPEMCertPool()
	for _, cert := range certs {
		if !pool.AppendCertsFromPEM([]byte(cert)) {
			t.Fatalf("couldn't parse test certs: %v", certs)
		}
	}
	return pool
}

func mustMarshalRoot(t *testing.T, lr *types.LogRootV1) *trillian.SignedLogRoot {
	t.Helper()
	rootBytes, err := lr.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal root in test: %v", err)
	}
	return &trillian.SignedLogRoot{
		LogRoot: rootBytes,
	}
}

// cmpMatcher is a custom gomock.Matcher that uses cmp.Equal combined with a
// cmp.Comparer that knows how to properly compare proto.Message types.
type cmpMatcher struct{ want interface{} }

func (m cmpMatcher) Matches(got interface{}) bool {
	return cmp.Equal(got, m.want, cmp.Comparer(proto.Equal))
}
func (m cmpMatcher) String() string {
	return fmt.Sprintf("equals %v", m.want)
}
