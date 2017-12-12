package audit

import (
	"encoding/base64"
	"testing"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/testdata"
	"github.com/google/certificate-transparency-go/tls"
)

func TestLeafHash(t *testing.T) {
	tests := []struct {
		desc     string
		chainPEM string
		sct      []byte
		want     string
	}{
		{
			desc:     "cert",
			chainPEM: testdata.TestCertPEM + testdata.CACertPEM,
			sct:      testdata.TestCertProof,
			want:     testdata.TestCertB64LeafHash,
		},
		{
			desc:     "precert",
			chainPEM: testdata.TestPreCertPEM + testdata.CACertPEM,
			sct:      testdata.TestPreCertProof,
			want:     testdata.TestPreCertB64LeafHash,
		},
	}

	for _, test := range tests {
		// Parse chain
		chain, err := ParseChainFromPEM([]byte(test.chainPEM))
		if err != nil {
			t.Errorf("%s: error parsing certificate chain: %s", test.desc, err)
			continue
		}

		// Parse SCT
		var sct ct.SignedCertificateTimestamp
		_, err = tls.Unmarshal(test.sct, &sct)
		if err != nil {
			t.Errorf("%s: error tls-unmarshalling sct: %s", test.desc, err)
			continue
		}

		// Test LeafHash()
		wantSl, err := base64.StdEncoding.DecodeString(test.want)
		if err != nil {
			t.Fatalf("%s: error base64-decoding leaf hash %q: %s", test.desc, test.want, err)
		}
		var want [32]byte
		copy(want[:], wantSl)

		got, err := LeafHash(chain, &sct)
		if got != want || err != nil {
			t.Errorf("%s: LeafHash(_,_) = %v, %v, want %v, nil", test.desc, got, err, want)
		}

		// Test B64LeafHash()
		gotB64, err := B64LeafHash(chain, &sct)
		if gotB64 != test.want || err != nil {
			t.Errorf("%s: B64LeafHash(_,_) = %v, %v, want %v, nil", test.desc, gotB64, err, test.want)
		}
	}
}

func TestLeafHashErrors(t *testing.T) {
	tests := []struct {
		desc     string
		chainPEM string
		sct      []byte
	}{
		{
			desc:     "empty chain",
			chainPEM: "",
			sct:      testdata.TestCertProof,
		},
		{
			desc:     "nil sct",
			chainPEM: testdata.TestCertPEM + testdata.CACertPEM,
			sct:      nil,
		},
	}

	for _, test := range tests {
		// Parse chain
		chain, err := ParseChainFromPEM([]byte(test.chainPEM))
		if err != nil {
			t.Errorf("%s: error parsing certificate chain: %s", test.desc, err)
			continue
		}

		// Parse SCT
		var sct *ct.SignedCertificateTimestamp
		if test.sct != nil {
			sct = &ct.SignedCertificateTimestamp{}
			_, err = tls.Unmarshal(test.sct, sct)
			if err != nil {
				t.Errorf("%s: error tls-unmarshalling sct: %s", test.desc, err)
				continue
			}
		}

		// Test LeafHash()
		got, err := LeafHash(chain, sct)
		if got != emptyHash || err == nil {
			t.Errorf("%s: LeafHash(_,_) = %s, %v, want %v, error", test.desc, got, err, emptyHash)
		}

		// Test B64LeafHash()
		gotB64, err := B64LeafHash(chain, sct)
		if gotB64 != "" || err == nil {
			t.Errorf("%s: B64LeafHash(_,_) = %s, %v, want \"\", error", test.desc, gotB64, err)
		}
	}
}

func TestIsPrecert(t *testing.T) {
	tests := []struct {
		desc    string
		certPEM string
		want    bool
	}{
		{
			desc:    "cert",
			certPEM: testdata.TestCertPEM,
			want:    false,
		},
		{
			desc:    "precert",
			certPEM: testdata.TestPreCertPEM,
			want:    true,
		},
	}

	for _, test := range tests {
		cert, err := ParseCertificateFromPEM([]byte(test.certPEM))
		if err != nil {
			t.Errorf("%s: error parsing certificate: %s", test.desc, err)
			continue
		}

		if got := IsPrecert(cert); got != test.want {
			t.Errorf("IsPrecert(%s) = %t, want %t", test.desc, got, test.want)
		}
	}
}

func TestVerifySCT(t *testing.T) {
	tests := []struct {
		desc     string
		chainPEM string
		sct      []byte
		wantErr  bool
	}{
		{
			desc:     "cert",
			chainPEM: testdata.TestCertPEM + testdata.CACertPEM,
			sct:      testdata.TestCertProof,
		},
		{
			desc:     "precert",
			chainPEM: testdata.TestPreCertPEM + testdata.CACertPEM,
			sct:      testdata.TestPreCertProof,
		},
		{
			desc:     "bad SCT",
			chainPEM: testdata.TestPreCertPEM + testdata.CACertPEM,
			sct:      testdata.TestCertProof,
			wantErr:  true,
		},
	}

	for _, test := range tests {
		// Parse chain
		chain, err := ParseChainFromPEM([]byte(test.chainPEM))
		if err != nil {
			t.Errorf("%s: error parsing certificate chain: %s", test.desc, err)
			continue
		}

		// Parse SCT
		var sct ct.SignedCertificateTimestamp
		_, err = tls.Unmarshal(test.sct, &sct)
		if err != nil {
			t.Errorf("%s: error tls-unmarshalling sct: %s", test.desc, err)
			continue
		}

		// Test VerifySCT()
		pk, err := ParseB64PublicKey(testdata.LogPublicKeyB64)
		if err != nil {
			t.Errorf("%s: error parsing public key: %s", test.desc, err)
		}

		err = VerifySCT(pk, chain, &sct)
		if gotErr := (err != nil); gotErr != test.wantErr {
			t.Errorf("%s: VerifySCT(_,_,_) = %v, want error? %t", test.desc, err, test.wantErr)
		}

		// Test VerifySCTB64PublicKey()
		err = VerifySCTB64PublicKey(testdata.LogPublicKeyB64, chain, &sct)
		if gotErr := (err != nil); gotErr != test.wantErr {
			t.Errorf("%s: VerifySCTB64PublicKey(_,_,_) = %v, want error? %t", test.desc, err, test.wantErr)
		}
	}
}
