package clientv2

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	ct "github.com/google/certificate-transparency/go"
	"github.com/google/certificate-transparency/go/jsonclient"
	"github.com/google/certificate-transparency/go/testdata"
	"github.com/google/certificate-transparency/go/tls"
	"golang.org/x/net/context"
)

func TestHasherForAlgorithm(t *testing.T) {
	var tests = []struct {
		algo   tls.HashAlgorithm
		errstr string
	}{
		{99, "unsupported hash algorithm"},
		{tls.SHA256, ""},
	}
	for _, test := range tests {
		got, err := hasherForAlgorithm(test.algo)
		if test.errstr != "" {
			if err == nil {
				t.Errorf("hasherForAlgorithm(%d)=%T, nil; want error %q", test.algo, got, test.errstr)
			} else if !strings.Contains(err.Error(), test.errstr) {
				t.Errorf("hasherForAlgorithm(%d)=nil,%q; want error %q", test.algo, err.Error(), test.errstr)
			}
			continue
		}
		if err != nil {
			t.Errorf("hasherForAlgorithm(%d)=nil,%q; want error nil", test.algo, err.Error())
		}
	}
}

func TestNewLogClient(t *testing.T) {
	var tests = []struct {
		algo   tls.HashAlgorithm
		pubKey string
		errstr string
	}{
		{tls.SHA256, "", ""},
		{tls.SHA256, testdata.EcdsaPublicKeyPEM, ""},
		{99, testdata.EcdsaPublicKeyPEM, "unsupported hash algorithm"},
		{tls.SHA256, testdata.EcdsaPublicKeyPEM + "junk", "extra data"},
	}
	for _, test := range tests {
		opts := Options{Options: jsonclient.Options{PublicKey: test.pubKey}, hashAlgo: test.algo}
		got, err := New("http://localhost", nil, opts)
		if test.errstr != "" {
			if err == nil {
				t.Errorf("clientv2.New(%q, %d)=%T, nil; want error %q", test.pubKey, test.algo, got, test.errstr)
			} else if !strings.Contains(err.Error(), test.errstr) {
				t.Errorf("clientv2.New(%q, %d)=nil,%q; want error %q", test.pubKey, test.algo, err.Error(), test.errstr)
			}
			continue
		}
		if err != nil {
			t.Errorf("clientv2.New(%d)=nil,%q; want error nil", test.pubKey, test.algo, err.Error())
		}
	}
}

func TestCheckSCTExtensions(t *testing.T) {
	var tests = []struct {
		exts   []ct.SCTExtension
		errstr string
	}{
		{
			exts: []ct.SCTExtension{
				ct.SCTExtension{SCTExtensionType: 1},
				ct.SCTExtension{SCTExtensionType: 2},
				ct.SCTExtension{SCTExtensionType: 4},
			},
		},
		{
			exts: []ct.SCTExtension{
				ct.SCTExtension{SCTExtensionType: 1},
				ct.SCTExtension{SCTExtensionType: 4},
				ct.SCTExtension{SCTExtensionType: 2},
			},
			errstr: "not ordered correctly",
		},
		{
			exts: []ct.SCTExtension{
				ct.SCTExtension{SCTExtensionType: 1},
				ct.SCTExtension{SCTExtensionType: 2},
				ct.SCTExtension{SCTExtensionType: 2},
			},
			errstr: "not ordered correctly",
		},
	}
	for _, test := range tests {
		err := checkSCTExtensions(test.exts)
		if test.errstr != "" {
			if err == nil {
				t.Errorf("checkSCTExtensions(%+v)=nil; want error %q", test.exts, test.errstr)
			} else if !strings.Contains(err.Error(), test.errstr) {
				t.Errorf("checkSCTExtensions(%+v)=%q; want error %q", test.exts, err.Error(), test.errstr)
			}
			continue
		}
		if err != nil {
			t.Errorf("checkSCTExtensions(%+v)=%q; want nil", test.exts, err.Error())
		}
	}
}

func TestGetSTH(t *testing.T) {
	makeSTH := func(s string) string {
		return fmt.Sprintf(`{"sth":"%s"}`, b64(s))
	}
	tests := []struct {
		rsp      string
		want     *ct.SignedTreeHeadDataV2
		noverify bool
		errstr   string
	}{
		{rsp: `{"sth":"not b64"}`, errstr: "illegal base64 data"},
		{rsp: `Not JSON data`, errstr: "invalid character"},
		{rsp: `{"sth-key":"missing"}`, errstr: "unexpected"},
		{rsp: makeSTH("61626364"), errstr: "syntax error"},
		{rsp: makeSTH("0005" + "022a03" + ("1122334455667788" + "0000000000000100" + "02cafe" + "0000") + "04030047" + testdata.EcdsaSignedAbcdHex), errstr: "failed to verify STH signature"},
		{
			rsp:      makeSTH("0005" + "022a03" + ("1122334455667788" + "0000000000000100" + "02cafe" + "0000") + "04030047" + testdata.EcdsaSignedAbcdHex),
			noverify: true,
			want: &ct.SignedTreeHeadDataV2{
				LogID: []byte{0x2a, 0x03},
				TreeHead: ct.TreeHeadDataV2{
					Timestamp:     0x1122334455667788,
					TreeSize:      0x0100,
					RootHash:      ct.NodeHash{Value: []byte{0xca, 0xfe}},
					STHExtensions: []ct.STHExtension{},
				},
				Signature: tls.DigitallySigned{
					Algorithm: tls.SignatureAndHashAlgorithm{
						Hash:      tls.SHA256,
						Signature: tls.ECDSA},
					Signature: testdata.FromHex(testdata.EcdsaSignedAbcdHex),
				},
			},
		},
	}

	for _, test := range tests {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/ct/v2/get-sth" {
				t.Fatalf("Incorrect URL path: %s", r.URL.Path)
			}
			fmt.Fprint(w, test.rsp)
		}))
		defer ts.Close()

		opts := Options{hashAlgo: tls.SHA256}
		if !test.noverify {
			opts.Options.PublicKey = testdata.EcdsaPublicKeyPEM
		}
		client, _ := New(ts.URL, nil, opts)
		got, err := client.GetSTH(context.Background())

		if test.errstr != "" {
			if err == nil {
				t.Errorf("GetSTH()=%+v,nil; want error %q", got, test.errstr)
			} else if !strings.Contains(err.Error(), test.errstr) {
				t.Errorf("GetSTH()=nil,%q; want error %q", err.Error(), test.errstr)
			}
			continue
		}
		if err != nil {
			t.Errorf("GetSTH()=nil,%q; want %+v", err.Error(), test.want)
		} else if !reflect.DeepEqual(test.want, got) {
			t.Errorf("GetSTH()=%+v,nil; want %+v", got, test.want)
		}

	}
}

var dehex = testdata.FromHex

func b64(hexData string) string {
	return base64.StdEncoding.EncodeToString(dehex(hexData))
}
