// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"bytes"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"net/url"
	"os/exec"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/certificate-transparency-go/asn1"
	"github.com/google/certificate-transparency-go/x509/pkix"
)

func TestParsePKCS1PrivateKey(t *testing.T) {
	block, _ := pem.Decode([]byte(pemPrivateKey))
	priv, err := ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Errorf("Failed to parse private key: %s", err)
		return
	}
	if priv.PublicKey.N.Cmp(rsaPrivateKey.PublicKey.N) != 0 ||
		priv.PublicKey.E != rsaPrivateKey.PublicKey.E ||
		priv.D.Cmp(rsaPrivateKey.D) != 0 ||
		priv.Primes[0].Cmp(rsaPrivateKey.Primes[0]) != 0 ||
		priv.Primes[1].Cmp(rsaPrivateKey.Primes[1]) != 0 {
		t.Errorf("got:%+v want:%+v", priv, rsaPrivateKey)
	}

	// This private key includes an invalid prime that
	// rsa.PrivateKey.Validate should reject.
	data := []byte("0\x16\x02\x00\x02\x02\u007f\x00\x02\x0200\x02\x0200\x02\x02\x00\x01\x02\x02\u007f\x00")
	if _, err := ParsePKCS1PrivateKey(data); err == nil {
		t.Errorf("parsing invalid private key did not result in an error")
	}
}

func TestParsePKIXPublicKey(t *testing.T) {
	block, _ := pem.Decode([]byte(pemPublicKey))
	pub, err := ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Errorf("Failed to parse RSA public key: %s", err)
		return
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Errorf("Value returned from ParsePKIXPublicKey was not an RSA public key")
		return
	}

	pubBytes2, err := MarshalPKIXPublicKey(rsaPub)
	if err != nil {
		t.Errorf("Failed to marshal RSA public key for the second time: %s", err)
		return
	}
	if !bytes.Equal(pubBytes2, block.Bytes) {
		t.Errorf("Reserialization of public key didn't match. got %x, want %x", pubBytes2, block.Bytes)
	}
}

var pemPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3VoPN9PKUjKFLMwOge6+
wnDi8sbETGIx2FKXGgqtAKpzmem53kRGEQg8WeqRmp12wgp74TGpkEXsGae7RS1k
enJCnma4fii+noGH7R0qKgHvPrI2Bwa9hzsH8tHxpyM3qrXslOmD45EH9SxIDUBJ
FehNdaPbLP1gFyahKMsdfxFJLUvbUycuZSJ2ZnIgeVxwm4qbSvZInL9Iu4FzuPtg
fINKcbbovy1qq4KvPIrXzhbY3PWDc6btxCf3SE0JdE1MCPThntB62/bLMSQ7xdDR
FF53oIpvxe/SCOymfWq/LW849Ytv3Xwod0+wzAP8STXG4HSELS4UedPYeHJJJYcZ
+QIDAQAB
-----END PUBLIC KEY-----
`

var pemPrivateKey = `
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCxoeCUW5KJxNPxMp+KmCxKLc1Zv9Ny+4CFqcUXVUYH69L3mQ7v
IWrJ9GBfcaA7BPQqUlWxWM+OCEQZH1EZNIuqRMNQVuIGCbz5UQ8w6tS0gcgdeGX7
J7jgCQ4RK3F/PuCM38QBLaHx988qG8NMc6VKErBjctCXFHQt14lerd5KpQIDAQAB
AoGAYrf6Hbk+mT5AI33k2Jt1kcweodBP7UkExkPxeuQzRVe0KVJw0EkcFhywKpr1
V5eLMrILWcJnpyHE5slWwtFHBG6a5fLaNtsBBtcAIfqTQ0Vfj5c6SzVaJv0Z5rOd
7gQF6isy3t3w9IF3We9wXQKzT6q5ypPGdm6fciKQ8RnzREkCQQDZwppKATqQ41/R
vhSj90fFifrGE6aVKC1hgSpxGQa4oIdsYYHwMzyhBmWW9Xv/R+fPyr8ZwPxp2c12
33QwOLPLAkEA0NNUb+z4ebVVHyvSwF5jhfJxigim+s49KuzJ1+A2RaSApGyBZiwS
rWvWkB471POAKUYt5ykIWVZ83zcceQiNTwJBAMJUFQZX5GDqWFc/zwGoKkeR49Yi
MTXIvf7Wmv6E++eFcnT461FlGAUHRV+bQQXGsItR/opIG7mGogIkVXa3E1MCQARX
AAA7eoZ9AEHflUeuLn9QJI/r0hyQQLEtrpwv6rDT1GCWaLII5HJ6NUFVf4TTcqxo
6vdM4QGKTJoO+SaCyP0CQFdpcxSAuzpFcKv0IlJ8XzS/cy+mweCMwyJ1PFEc4FX6
wg/HcAJWY60xZTJDFN+Qfx8ZQvBEin6c2/h+zZi5IVY=
-----END RSA PRIVATE KEY-----
`

var testPrivateKey *rsa.PrivateKey

func init() {
	block, _ := pem.Decode([]byte(pemPrivateKey))

	var err error
	if testPrivateKey, err = ParsePKCS1PrivateKey(block.Bytes); err != nil {
		panic("Failed to parse private key: " + err.Error())
	}
}

func bigFromString(s string) *big.Int {
	ret := new(big.Int)
	ret.SetString(s, 10)
	return ret
}

func fromBase10(base10 string) *big.Int {
	i := new(big.Int)
	i.SetString(base10, 10)
	return i
}

func bigFromHexString(s string) *big.Int {
	ret := new(big.Int)
	ret.SetString(s, 16)
	return ret
}

var rsaPrivateKey = &rsa.PrivateKey{
	PublicKey: rsa.PublicKey{
		N: bigFromString("124737666279038955318614287965056875799409043964547386061640914307192830334599556034328900586693254156136128122194531292927142396093148164407300419162827624945636708870992355233833321488652786796134504707628792159725681555822420087112284637501705261187690946267527866880072856272532711620639179596808018872997"),
		E: 65537,
	},
	D: bigFromString("69322600686866301945688231018559005300304807960033948687567105312977055197015197977971637657636780793670599180105424702854759606794705928621125408040473426339714144598640466128488132656829419518221592374964225347786430566310906679585739468938549035854760501049443920822523780156843263434219450229353270690889"),
	Primes: []*big.Int{
		bigFromString("11405025354575369741595561190164746858706645478381139288033759331174478411254205003127028642766986913445391069745480057674348716675323735886284176682955723"),
		bigFromString("10937079261204603443118731009201819560867324167189758120988909645641782263430128449826989846631183550578761324239709121189827307416350485191350050332642639"),
	},
}

func TestMarshalRSAPrivateKey(t *testing.T) {
	priv := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: fromBase10("16346378922382193400538269749936049106320265317511766357599732575277382844051791096569333808598921852351577762718529818072849191122419410612033592401403764925096136759934497687765453905884149505175426053037420486697072448609022753683683718057795566811401938833367954642951433473337066311978821180526439641496973296037000052546108507805269279414789035461158073156772151892452251106173507240488993608650881929629163465099476849643165682709047462010581308719577053905787496296934240246311806555924593059995202856826239801816771116902778517096212527979497399966526283516447337775509777558018145573127308919204297111496233"),
			E: 3,
		},
		D: fromBase10("10897585948254795600358846499957366070880176878341177571733155050184921896034527397712889205732614568234385175145686545381899460748279607074689061600935843283397424506622998458510302603922766336783617368686090042765718290914099334449154829375179958369993407724946186243249568928237086215759259909861748642124071874879861299389874230489928271621259294894142840428407196932444474088857746123104978617098858619445675532587787023228852383149557470077802718705420275739737958953794088728369933811184572620857678792001136676902250566845618813972833750098806496641114644760255910789397593428910198080271317419213080834885003"),
		Primes: []*big.Int{
			fromBase10("1025363189502892836833747188838978207017355117492483312747347695538428729137306368764177201532277413433182799108299960196606011786562992097313508180436744488171474690412562218914213688661311117337381958560443"),
			fromBase10("3467903426626310123395340254094941045497208049900750380025518552334536945536837294961497712862519984786362199788654739924501424784631315081391467293694361474867825728031147665777546570788493758372218019373"),
			fromBase10("4597024781409332673052708605078359346966325141767460991205742124888960305710298765592730135879076084498363772408626791576005136245060321874472727132746643162385746062759369754202494417496879741537284589047"),
		},
	}

	derBytes := MarshalPKCS1PrivateKey(priv)

	priv2, err := ParsePKCS1PrivateKey(derBytes)
	if err != nil {
		t.Errorf("error parsing serialized key: %s", err)
		return
	}
	if priv.PublicKey.N.Cmp(priv2.PublicKey.N) != 0 ||
		priv.PublicKey.E != priv2.PublicKey.E ||
		priv.D.Cmp(priv2.D) != 0 ||
		len(priv2.Primes) != 3 ||
		priv.Primes[0].Cmp(priv2.Primes[0]) != 0 ||
		priv.Primes[1].Cmp(priv2.Primes[1]) != 0 ||
		priv.Primes[2].Cmp(priv2.Primes[2]) != 0 {
		t.Errorf("got:%+v want:%+v", priv, priv2)
	}
}

func TestMarshalRSAPublicKey(t *testing.T) {
	pub := &rsa.PublicKey{
		N: fromBase10("16346378922382193400538269749936049106320265317511766357599732575277382844051791096569333808598921852351577762718529818072849191122419410612033592401403764925096136759934497687765453905884149505175426053037420486697072448609022753683683718057795566811401938833367954642951433473337066311978821180526439641496973296037000052546108507805269279414789035461158073156772151892452251106173507240488993608650881929629163465099476849643165682709047462010581308719577053905787496296934240246311806555924593059995202856826239801816771116902778517096212527979497399966526283516447337775509777558018145573127308919204297111496233"),
		E: 3,
	}
	derBytes := MarshalPKCS1PublicKey(pub)
	pub2, err := ParsePKCS1PublicKey(derBytes)
	if err != nil {
		t.Errorf("ParsePKCS1PublicKey: %s", err)
	}
	if pub.N.Cmp(pub2.N) != 0 || pub.E != pub2.E {
		t.Errorf("ParsePKCS1PublicKey = %+v, want %+v", pub, pub2)
	}

	// It's never been documented that asn1.Marshal/Unmarshal on rsa.PublicKey works,
	// but it does, and we know of code that depends on it.
	// Lock that in, even though we'd prefer that people use MarshalPKCS1PublicKey and ParsePKCS1PublicKey.
	derBytes2, err := asn1.Marshal(*pub)
	if err != nil {
		t.Errorf("Marshal(rsa.PublicKey): %v", err)
	} else if !bytes.Equal(derBytes, derBytes2) {
		t.Errorf("Marshal(rsa.PublicKey) = %x, want %x", derBytes2, derBytes)
	}
	pub3 := new(rsa.PublicKey)
	rest, err := asn1.Unmarshal(derBytes, pub3)
	if err != nil {
		t.Errorf("Unmarshal(rsa.PublicKey): %v", err)
	}
	if len(rest) != 0 || pub.N.Cmp(pub3.N) != 0 || pub.E != pub3.E {
		t.Errorf("Unmarshal(rsa.PublicKey) = %+v, %q want %+v, %q", pub, rest, pub2, []byte(nil))
	}

	publicKeys := []struct {
		derBytes          []byte
		expectedErrSubstr string
	}{
		{
			derBytes: []byte{
				0x30, 6, // SEQUENCE, 6 bytes
				0x02, 1, // INTEGER, 1 byte
				17,
				0x02, 1, // INTEGER, 1 byte
				3, // 3
			},
		}, {
			derBytes: []byte{
				0x30, 6, // SEQUENCE
				0x02, 1, // INTEGER, 1 byte
				0xff,    // -1
				0x02, 1, // INTEGER, 1 byte
				3,
			},
			expectedErrSubstr: "zero or negative",
		}, {
			derBytes: []byte{
				0x30, 6, // SEQUENCE
				0x02, 1, // INTEGER, 1 byte
				17,
				0x02, 1, // INTEGER, 1 byte
				0xff, // -1
			},
			expectedErrSubstr: "zero or negative",
		}, {
			derBytes: []byte{
				0x30, 6, // SEQUENCE
				0x02, 1, // INTEGER, 1 byte
				17,
				0x02, 1, // INTEGER, 1 byte
				3,
				1,
			},
			expectedErrSubstr: "trailing data",
		}, {
			derBytes: []byte{
				0x30, 9, // SEQUENCE
				0x02, 1, // INTEGER, 1 byte
				17,
				0x02, 4, // INTEGER, 4 bytes
				0x7f, 0xff, 0xff, 0xff,
			},
		}, {
			derBytes: []byte{
				0x30, 10, // SEQUENCE
				0x02, 1, // INTEGER, 1 byte
				17,
				0x02, 5, // INTEGER, 5 bytes
				0x00, 0x80, 0x00, 0x00, 0x00,
			},
			// On 64-bit systems, encoding/asn1 will accept the
			// public exponent, but ParsePKCS1PublicKey will return
			// an error. On 32-bit systems, encoding/asn1 will
			// return the error. The common substring of both error
			// is the word “large”.
			expectedErrSubstr: "large",
		},
	}

	for i, test := range publicKeys {
		shouldFail := len(test.expectedErrSubstr) > 0
		pub, err := ParsePKCS1PublicKey(test.derBytes)
		if shouldFail {
			if err == nil {
				t.Errorf("#%d: unexpected success, got %#v", i, pub)
			} else if !strings.Contains(err.Error(), test.expectedErrSubstr) {
				t.Errorf("#%d: expected error containing %q, got %s", i, test.expectedErrSubstr, err)
			}
		} else {
			if err != nil {
				t.Errorf("#%d: unexpected failure: %s", i, err)
				continue
			}
			reserialized := MarshalPKCS1PublicKey(pub)
			if !bytes.Equal(reserialized, test.derBytes) {
				t.Errorf("#%d: failed to reserialize: got %x, expected %x", i, reserialized, test.derBytes)
			}
		}
	}
}

type matchHostnamesTest struct {
	pattern, host string
	ok            bool
}

var matchHostnamesTests = []matchHostnamesTest{
	{"a.b.c", "a.b.c", true},
	{"a.b.c", "b.b.c", false},
	{"", "b.b.c", false},
	{"a.b.c", "", false},
	{"example.com", "example.com", true},
	{"example.com", "www.example.com", false},
	{"*.example.com", "example.com", false},
	{"*.example.com", "www.example.com", true},
	{"*.example.com", "www.example.com.", true},
	{"*.example.com", "xyz.www.example.com", false},
	{"*.*.example.com", "xyz.www.example.com", false},
	{"*.www.*.com", "xyz.www.example.com", false},
	{"*bar.example.com", "foobar.example.com", false},
	{"f*.example.com", "foobar.example.com", false},
	{"", ".", false},
	{".", "", false},
	{".", ".", false},
	{"example.com", "example.com.", true},
	{"example.com.", "example.com", true},
	{"example.com.", "example.com.", true},
	{"*.com.", "example.com.", true},
	{"*.com.", "example.com", true},
	{"*.com", "example.com", true},
	{"*.com", "example.com.", true},
}

func TestMatchHostnames(t *testing.T) {
	for i, test := range matchHostnamesTests {
		r := matchHostnames(test.pattern, test.host)
		if r != test.ok {
			t.Errorf("#%d mismatch got: %t want: %t when matching '%s' against '%s'", i, r, test.ok, test.host, test.pattern)
		}
	}
}

func TestMatchIP(t *testing.T) {
	// Check that pattern matching is working.
	c := &Certificate{
		DNSNames: []string{"*.foo.bar.baz"},
		Subject: pkix.Name{
			CommonName: "*.foo.bar.baz",
		},
	}
	err := c.VerifyHostname("quux.foo.bar.baz")
	if err != nil {
		t.Fatalf("VerifyHostname(quux.foo.bar.baz): %v", err)
	}

	// But check that if we change it to be matching against an IP address,
	// it is rejected.
	c = &Certificate{
		DNSNames: []string{"*.2.3.4"},
		Subject: pkix.Name{
			CommonName: "*.2.3.4",
		},
	}
	err = c.VerifyHostname("1.2.3.4")
	if err == nil {
		t.Fatalf("VerifyHostname(1.2.3.4) should have failed, did not")
	}

	c = &Certificate{
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	err = c.VerifyHostname("127.0.0.1")
	if err != nil {
		t.Fatalf("VerifyHostname(127.0.0.1): %v", err)
	}
	err = c.VerifyHostname("::1")
	if err != nil {
		t.Fatalf("VerifyHostname(::1): %v", err)
	}
	err = c.VerifyHostname("[::1]")
	if err != nil {
		t.Fatalf("VerifyHostname([::1]): %v", err)
	}
}

func TestCertificateParse(t *testing.T) {
	s, _ := hex.DecodeString(certBytes)
	certs, err := ParseCertificates(s)
	if IsFatal(err) {
		t.Error(err)
	}
	if len(certs) != 2 {
		t.Errorf("Wrong number of certs: got %d want 2", len(certs))
		return
	}

	err = certs[0].CheckSignatureFrom(certs[1])
	if err != nil {
		t.Error(err)
	}

	if err := certs[0].VerifyHostname("mail.google.com"); err != nil {
		t.Error(err)
	}

	const expectedExtensions = 4
	if n := len(certs[0].Extensions); n != expectedExtensions {
		t.Errorf("want %d extensions, got %d", expectedExtensions, n)
	}
}

func TestMismatchedSignatureAlgorithm(t *testing.T) {
	der, _ := pem.Decode([]byte(rsaPSSSelfSignedPEM))
	if der == nil {
		t.Fatal("Failed to find PEM block")
	}

	cert, err := ParseCertificate(der.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	if err = cert.CheckSignature(ECDSAWithSHA256, nil, nil); err == nil {
		t.Fatal("CheckSignature unexpectedly return no error")
	}

	const expectedSubstring = " but have public key of type "
	if !strings.Contains(err.Error(), expectedSubstring) {
		t.Errorf("Expected error containing %q, but got %q", expectedSubstring, err)
	}
}

var certBytes = "308203223082028ba00302010202106edf0d9499fd4533dd1297fc42a93be1300d06092a864886" +
	"f70d0101050500304c310b3009060355040613025a4131253023060355040a131c546861777465" +
	"20436f6e73756c74696e67202850747929204c74642e311630140603550403130d546861777465" +
	"20534743204341301e170d3039303332353136343932395a170d3130303332353136343932395a" +
	"3069310b3009060355040613025553311330110603550408130a43616c69666f726e6961311630" +
	"140603550407130d4d6f756e7461696e205669657731133011060355040a130a476f6f676c6520" +
	"496e63311830160603550403130f6d61696c2e676f6f676c652e636f6d30819f300d06092a8648" +
	"86f70d010101050003818d0030818902818100c5d6f892fccaf5614b064149e80a2c9581a218ef" +
	"41ec35bd7a58125ae76f9ea54ddc893abbeb029f6b73616bf0ffd868791fba7af9c4aebf3706ba" +
	"3eeaeed27435b4ddcfb157c05f351d66aa87fee0de072d66d773affbd36ab78bef090e0cc861a9" +
	"03ac90dd98b51c9c41566c017f0beec3bff391051ffba0f5cc6850ad2a590203010001a381e730" +
	"81e430280603551d250421301f06082b0601050507030106082b06010505070302060960864801" +
	"86f842040130360603551d1f042f302d302ba029a0278625687474703a2f2f63726c2e74686177" +
	"74652e636f6d2f54686177746553474343412e63726c307206082b060105050701010466306430" +
	"2206082b060105050730018616687474703a2f2f6f6373702e7468617774652e636f6d303e0608" +
	"2b060105050730028632687474703a2f2f7777772e7468617774652e636f6d2f7265706f736974" +
	"6f72792f5468617774655f5347435f43412e637274300c0603551d130101ff04023000300d0609" +
	"2a864886f70d01010505000381810062f1f3050ebc105e497c7aedf87e24d2f4a986bb3b837bd1" +
	"9b91ebcad98b065992f6bd2b49b7d6d3cb2e427a99d606c7b1d46352527fac39e6a8b6726de5bf" +
	"70212a52cba07634a5e332011bd1868e78eb5e3c93cf03072276786f207494feaa0ed9d53b2110" +
	"a76571f90209cdae884385c882587030ee15f33d761e2e45a6bc308203233082028ca003020102" +
	"020430000002300d06092a864886f70d0101050500305f310b3009060355040613025553311730" +
	"15060355040a130e566572695369676e2c20496e632e31373035060355040b132e436c61737320" +
	"33205075626c6963205072696d6172792043657274696669636174696f6e20417574686f726974" +
	"79301e170d3034303531333030303030305a170d3134303531323233353935395a304c310b3009" +
	"060355040613025a4131253023060355040a131c54686177746520436f6e73756c74696e672028" +
	"50747929204c74642e311630140603550403130d5468617774652053474320434130819f300d06" +
	"092a864886f70d010101050003818d0030818902818100d4d367d08d157faecd31fe7d1d91a13f" +
	"0b713cacccc864fb63fc324b0794bd6f80ba2fe10493c033fc093323e90b742b71c403c6d2cde2" +
	"2ff50963cdff48a500bfe0e7f388b72d32de9836e60aad007bc4644a3b847503f270927d0e62f5" +
	"21ab693684317590f8bfc76c881b06957cc9e5a8de75a12c7a68dfd5ca1c875860190203010001" +
	"a381fe3081fb30120603551d130101ff040830060101ff020100300b0603551d0f040403020106" +
	"301106096086480186f842010104040302010630280603551d110421301fa41d301b3119301706" +
	"035504031310507269766174654c6162656c332d313530310603551d1f042a30283026a024a022" +
	"8620687474703a2f2f63726c2e766572697369676e2e636f6d2f706361332e63726c303206082b" +
	"0601050507010104263024302206082b060105050730018616687474703a2f2f6f6373702e7468" +
	"617774652e636f6d30340603551d25042d302b06082b0601050507030106082b06010505070302" +
	"06096086480186f8420401060a6086480186f845010801300d06092a864886f70d010105050003" +
	"81810055ac63eadea1ddd2905f9f0bce76be13518f93d9052bc81b774bad6950a1eededcfddb07" +
	"e9e83994dcab72792f06bfab8170c4a8edea5334edef1e53d906c7562bd15cf4d18a8eb42bb137" +
	"9048084225c53e8acb7feb6f04d16dc574a2f7a27c7b603c77cd0ece48027f012fb69b37e02a2a" +
	"36dcd585d6ace53f546f961e05af"

var certWithSCTListPEM = `
-----BEGIN CERTIFICATE-----
MIIHkzCCBnugAwIBAgIUHz6ZOwEjk6zhU9v3n2Jo3qeucqYwDQYJKoZIhvcNAQEL
BQAwSTELMAkGA1UEBhMCQk0xGTAXBgNVBAoTEFF1b1ZhZGlzIExpbWl0ZWQxHzAd
BgNVBAMTFlF1b1ZhZGlzIEVWIFNTTCBJQ0EgRzEwHhcNMTcwMjA4MTQxNTU3WhcN
MTgwMjA4MTQyNTAwWjCByzETMBEGCysGAQQBgjc8AgEDEwJHQjEYMBYGA1UEDwwP
QnVzaW5lc3MgRW50aXR5MREwDwYDVQQFEwhTQzA5NTAwMDELMAkGA1UEBhMCR0Ix
EjAQBgNVBAgMCUVkaW5idXJnaDESMBAGA1UEBwwJRWRpbmJ1cmdoMSEwHwYDVQQK
DBhMbG95ZHMgQmFua2luZyBHcm91cCBQTEMxEjAQBgNVBAsMCUdST1VQIElUMjEb
MBkGA1UEAwwSd3d3Lmxsb3lkc2JhbmsuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAyRkzN3UmnYbuIW7V4P5qyF/3iCdJwaw/avb0tpOJTa/svtM2
9KxtVtgwqAPCSuWgjHh6lx+OzXBOh0cM1+gOvjscIJ7k6J0UKouhxrZ02G6CHiNS
0P3ztsW1CVYAnEQqnhC+hBSl+Ut7DdcsReOUaUrIbO8T0psfsBnez6VtcLB74Hi0
y6s2AOwPKG7zRjMcMEylOYyGMrUI4ooGsf7IBzMOdMZpkAMUEe6KZ/8AssZOH7F9
OacCBcGHwN3qp/AG02+tXGaS9DWCS9/seMWqyhE8YPk+iGV3sFZEueBMxixVObFZ
0Ezwv3cCel6v2mlA5OweteDI57VG4/7OI45CawIDAQABo4ID7jCCA+owdwYIKwYB
BQUHAQEEazBpMDgGCCsGAQUFBzAChixodHRwOi8vdHJ1c3QucXVvdmFkaXNnbG9i
YWwuY29tL3F2ZXZzc2wxLmNydDAtBggrBgEFBQcwAYYhaHR0cDovL2V2Lm9jc3Au
cXVvdmFkaXNnbG9iYWwuY29tMB0GA1UdDgQWBBSIASoK0Cmqs5B06CJUUzq5nQ6c
IDAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFFVYhs66fHZOmROpD9Nsn8L10zzj
MFEGA1UdIARKMEgwRgYMKwYBBAG+WAACZAECMDYwNAYIKwYBBQUHAgEWKGh0dHA6
Ly93d3cucXVvdmFkaXNnbG9iYWwuY29tL3JlcG9zaXRvcnkwOwYDVR0fBDQwMjAw
oC6gLIYqaHR0cDovL2NybC5xdW92YWRpc2dsb2JhbC5jb20vcXZldnNzbDEuY3Js
MA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEw
gd8GA1UdEQSB1zCB1IISd3d3Lmxsb3lkc2JhbmsuY29tghRzdGF0aWMuaGFsaWZh
eC5jby51a4IUd3d3Lmxsb3lkc2JhbmsuY28udWuCFGltYWdlcy5oYWxpZmF4LmNv
LnVrghh3d3cuYmFua29mc2NvdGxhbmQuY28udWuCD3d3dy5oYWxpZmF4LmNvbYIT
d3d3Lmxsb3lkc3RzYi5jby51a4IRd3d3Lmxsb3lkc3RzYi5jb22CEXd3dy5oYWxp
ZmF4LmNvLnVrghZ3d3cuYmFua29mc2NvdGxhbmQuY29tMIIBfgYKKwYBBAHWeQIE
AgSCAW4EggFqAWgAdgC72d+8H4pxtZOUI5eqkntHOFeVCqtS6BqQlmQ2jh7RhQAA
AVoeHdwIAAAEAwBHMEUCIQD3fh/6Cp3I44poKfhA7IkhjInvl8qC9JkooycB7NfE
lgIgMihc8F0Ap1gIU7WUCxWgV0nUxeWp34mp+g0IPnNJ1KcAdgCkuQmQtBhYFIe7
E6LMZ3AKPDWYBPkb37jjd80OyA3cEAAAAVoeHdwaAAAEAwBHMEUCIA45u9pfeirN
Hn8K0xHDCUfCihQSFJo0YYmFxYEgO8GEAiEAwDXdmIkkv3lJ1td+RjTzXMBIjp9R
3Ii1GumOGKe8IqcAdgBWFAaaL9fC7NP14b1Esj7HRna5vJkRXMDvlJhV1onQ3QAA
AVoeHdxAAAAEAwBHMEUCIEfe5grRiTvaHZJ4e4glbGftZ87n1pQf2lVeyBMUq0Xa
AiEA/+W+qCcVd3hHVaYJryO67SYCbUBinU5/6je8eDLOEM4wDQYJKoZIhvcNAQEL
BQADggEBADGdRf8XpQRPzxv+NeUr5i4q49JI8M/umbwSEXkHJmaDD4CDiUGkFUNR
Tte0HDRvjbu5y9xub09MgdMl84qvfjsph54rUVK7LWVphi6CC21XbRP5gEwKBeA2
wAZU1IhhWBy6DaW4CjpTu1Ji3FJqHqKklFrZTMSS+xoqfYbbN96q1mJHQhyDdRlC
JvNuS1lDM0u3+g/MHNpQM1aGZVKtwpzRABIYhydSJrO14TzWJjbKm1UTnKiwvHbt
p1ATnYNDZKj3Ec8EASXGTHHoorX0jZpMiNxHv4p4BUinsNFttkhudMGbCfbjjqef
UfUJESblkeQVpcnndMfnsHSahCVd96k=
-----END CERTIFICATE-----
`

// The cert above contains the following SCTs, each of which is a TLS-encoded
// SignedCertificateTimestamp structure from RFC6962 s3.2.
/*
   struct {
       Version sct_version;
       LogID id;
       uint64 timestamp;
       CtExtensions extensions;
       digitally-signed struct {
           Version sct_version;
           SignatureType signature_type = certificate_timestamp;
           uint64 timestamp;
           LogEntryType entry_type;
           select(entry_type) {
               case x509_entry: ASN.1Cert;
               case precert_entry: PreCert;
           } signed_entry;
          CtExtensions extensions;
       };
   } SignedCertificateTimestamp;
*/

var wantSCTs = []string{
	("00" + // Version: v1(0)
		"bbd9dfbc1f8a71b593942397aa927b473857950aab52e81a909664368e1ed185" + // LogID: Google Skydiver
		"0000015a1e1ddc08" + // Timestamp
		"0000" + // No Extensions
		("04" + "03" + // SHA-256, ECDSA
			("0047" +
				"3045022100f77e1ffa0a9dc8e38a6829f840ec89218c89ef97ca82f49928a32701ecd7c496022032285cf05d00a7580853b5940b15a05749d4c5e5a9df89a9fa0d083e7349d4a7"))),

	("00" + // Version: v1(0)
		"a4b90990b418581487bb13a2cc67700a3c359804f91bdfb8e377cd0ec80ddc10" + // LogID: Google Pilot
		"0000015a1e1ddc1a" +
		"0000" + // No Extensions
		("04" + "03" + // SHA-256, ECDSA
			("0047" +
				"304502200e39bbda5f7a2acd1e7f0ad311c30947c28a1412149a34618985c581203bc184022100c035dd988924bf7949d6d77e4634f35cc0488e9f51dc88b51ae98e18a7bc22a7"))),
	("00" + // Version: v1(0)
		"5614069a2fd7c2ecd3f5e1bd44b23ec74676b9bc99115cc0ef949855d689d0dd" + // LogID: Digicert Log Server
		"0000015a1e1ddc40" + // Timestamp
		"0000" + // No Extensions
		("04" + "03" + // SHA-256, ECDSA
			("0047" +
				"3045022047dee60ad1893bda1d92787b88256c67ed67cee7d6941fda555ec81314ab45da022100ffe5bea8271577784755a609af23baed26026d40629d4e7fea37bc7832ce10ce"))),
}

func TestParseCertificateSCTs(t *testing.T) {
	pemBlock, _ := pem.Decode([]byte(certWithSCTListPEM))
	cert, err := ParseCertificate(pemBlock.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate()=_,%v; want _, nil", err)
	}
	if len(cert.RawSCT) == 0 {
		t.Errorf("len(cert.RawSCT)=0, want >0")
	}
	for i, got := range cert.SCTList.SCTList {
		want, _ := hex.DecodeString(wantSCTs[i])
		if !bytes.Equal(got.Val, want) {
			t.Errorf("SCT[%d]=%x; want %x", i, got.Val, want)
		}
	}
}

func parseCIDR(s string) *net.IPNet {
	_, net, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return net
}

func parseURI(s string) *url.URL {
	uri, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return uri
}

func TestCreateSelfSignedCertificate(t *testing.T) {
	random := rand.Reader

	ecdsaPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %s", err)
	}

	tests := []struct {
		name      string
		pub, priv interface{}
		checkSig  bool
		sigAlgo   SignatureAlgorithm
	}{
		{"RSA/RSA", &testPrivateKey.PublicKey, testPrivateKey, true, SHA1WithRSA},
		{"RSA/ECDSA", &testPrivateKey.PublicKey, ecdsaPriv, false, ECDSAWithSHA384},
		{"ECDSA/RSA", &ecdsaPriv.PublicKey, testPrivateKey, false, SHA256WithRSA},
		{"ECDSA/ECDSA", &ecdsaPriv.PublicKey, ecdsaPriv, true, ECDSAWithSHA1},
		{"RSAPSS/RSAPSS", &testPrivateKey.PublicKey, testPrivateKey, true, SHA256WithRSAPSS},
		{"ECDSA/RSAPSS", &ecdsaPriv.PublicKey, testPrivateKey, false, SHA256WithRSAPSS},
		{"RSAPSS/ECDSA", &testPrivateKey.PublicKey, ecdsaPriv, false, ECDSAWithSHA384},
	}

	testExtKeyUsage := []ExtKeyUsage{ExtKeyUsageClientAuth, ExtKeyUsageServerAuth}
	testUnknownExtKeyUsage := []asn1.ObjectIdentifier{[]int{1, 2, 3}, []int{2, 59, 1}}
	extraExtensionData := []byte("extra extension")

	for _, test := range tests {
		commonName := "test.example.com"
		template := Certificate{
			// SerialNumber is negative to ensure that negative
			// values are parsed. This is due to the prevalence of
			// buggy code that produces certificates with negative
			// serial numbers.
			SerialNumber: big.NewInt(-1),
			Subject: pkix.Name{
				CommonName:   commonName,
				Organization: []string{"Σ Acme Co"},
				Country:      []string{"US"},
				ExtraNames: []pkix.AttributeTypeAndValue{
					{
						Type:  []int{2, 5, 4, 42},
						Value: "Gopher",
					},
					// This should override the Country, above.
					{
						Type:  []int{2, 5, 4, 6},
						Value: "NL",
					},
				},
			},
			NotBefore: time.Unix(1000, 0),
			NotAfter:  time.Unix(100000, 0),

			SignatureAlgorithm: test.sigAlgo,

			SubjectKeyId: []byte{1, 2, 3, 4},
			KeyUsage:     KeyUsageCertSign,

			ExtKeyUsage:        testExtKeyUsage,
			UnknownExtKeyUsage: testUnknownExtKeyUsage,

			BasicConstraintsValid: true,
			IsCA: true,

			OCSPServer:            []string{"http://ocsp.example.com"},
			IssuingCertificateURL: []string{"http://crt.example.com/ca1.crt"},

			DNSNames:       []string{"test.example.com"},
			EmailAddresses: []string{"gopher@golang.org"},
			IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},
			URIs:           []*url.URL{parseURI("https://foo.com/wibble#foo")},

			PolicyIdentifiers:       []asn1.ObjectIdentifier{[]int{1, 2, 3}},
			PermittedDNSDomains:     []string{".example.com", "example.com"},
			ExcludedDNSDomains:      []string{"bar.example.com"},
			PermittedIPRanges:       []*net.IPNet{parseCIDR("192.168.1.1/16"), parseCIDR("1.2.3.4/8")},
			ExcludedIPRanges:        []*net.IPNet{parseCIDR("2001:db8::/48")},
			PermittedEmailAddresses: []string{"foo@example.com"},
			ExcludedEmailAddresses:  []string{".example.com", "example.com"},
			PermittedURIDomains:     []string{".bar.com", "bar.com"},
			ExcludedURIDomains:      []string{".bar2.com", "bar2.com"},

			CRLDistributionPoints: []string{"http://crl1.example.com/ca1.crl", "http://crl2.example.com/ca1.crl"},

			RawSCT: []byte{0xde, 0xad}, // Ignored because SCTList provided.
			SCTList: SignedCertificateTimestampList{
				SCTList: []SerializedSCT{
					{Val: []byte{0x01, 0x02, 0x03}},
					{Val: []byte{0x04, 0x05, 0x06}},
				},
			},

			ExtraExtensions: []pkix.Extension{
				{
					Id:    []int{1, 2, 3, 4},
					Value: extraExtensionData,
				},
				// This extension should override the SubjectKeyId, above.
				{
					Id:       OIDExtensionSubjectKeyId,
					Critical: false,
					Value:    []byte{0x04, 0x04, 4, 3, 2, 1},
				},
			},
		}

		derBytes, err := CreateCertificate(random, &template, &template, test.pub, test.priv)
		if err != nil {
			t.Errorf("%s: failed to create certificate: %s", test.name, err)
			continue
		}

		cert, err := ParseCertificate(derBytes)
		if err != nil {
			t.Errorf("%s: failed to parse certificate: %s", test.name, err)
			continue
		}

		if len(cert.PolicyIdentifiers) != 1 || !cert.PolicyIdentifiers[0].Equal(template.PolicyIdentifiers[0]) {
			t.Errorf("%s: failed to parse policy identifiers: got:%#v want:%#v", test.name, cert.PolicyIdentifiers, template.PolicyIdentifiers)
		}

		if len(cert.PermittedDNSDomains) != 2 || cert.PermittedDNSDomains[0] != ".example.com" || cert.PermittedDNSDomains[1] != "example.com" {
			t.Errorf("%s: failed to parse name constraints: %#v", test.name, cert.PermittedDNSDomains)
		}

		if len(cert.ExcludedDNSDomains) != 1 || cert.ExcludedDNSDomains[0] != "bar.example.com" {
			t.Errorf("%s: failed to parse name constraint exclusions: %#v", test.name, cert.ExcludedDNSDomains)
		}

		if len(cert.PermittedIPRanges) != 2 || cert.PermittedIPRanges[0].String() != "192.168.0.0/16" || cert.PermittedIPRanges[1].String() != "1.0.0.0/8" {
			t.Errorf("%s: failed to parse IP constraints: %#v", test.name, cert.PermittedIPRanges)
		}

		if len(cert.ExcludedIPRanges) != 1 || cert.ExcludedIPRanges[0].String() != "2001:db8::/48" {
			t.Errorf("%s: failed to parse IP constraint exclusions: %#v", test.name, cert.ExcludedIPRanges)
		}

		if len(cert.PermittedEmailAddresses) != 1 || cert.PermittedEmailAddresses[0] != "foo@example.com" {
			t.Errorf("%s: failed to parse permitted email addreses: %#v", test.name, cert.PermittedEmailAddresses)
		}

		if len(cert.ExcludedEmailAddresses) != 2 || cert.ExcludedEmailAddresses[0] != ".example.com" || cert.ExcludedEmailAddresses[1] != "example.com" {
			t.Errorf("%s: failed to parse excluded email addreses: %#v", test.name, cert.ExcludedEmailAddresses)
		}

		if len(cert.PermittedURIDomains) != 2 || cert.PermittedURIDomains[0] != ".bar.com" || cert.PermittedURIDomains[1] != "bar.com" {
			t.Errorf("%s: failed to parse permitted URIs: %#v", test.name, cert.PermittedURIDomains)
		}

		if len(cert.ExcludedURIDomains) != 2 || cert.ExcludedURIDomains[0] != ".bar2.com" || cert.ExcludedURIDomains[1] != "bar2.com" {
			t.Errorf("%s: failed to parse excluded URIs: %#v", test.name, cert.ExcludedURIDomains)
		}

		if cert.Subject.CommonName != commonName {
			t.Errorf("%s: subject wasn't correctly copied from the template. Got %s, want %s", test.name, cert.Subject.CommonName, commonName)
		}

		if len(cert.Subject.Country) != 1 || cert.Subject.Country[0] != "NL" {
			t.Errorf("%s: ExtraNames didn't override Country", test.name)
		}

		for _, ext := range cert.Extensions {
			if ext.Id.Equal(OIDExtensionSubjectAltName) {
				if ext.Critical {
					t.Fatal("SAN extension is marked critical")
				}
			}
		}

		found := false
		for _, atv := range cert.Subject.Names {
			if atv.Type.Equal([]int{2, 5, 4, 42}) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s: Names didn't contain oid 2.5.4.42 from ExtraNames", test.name)
		}

		if cert.Issuer.CommonName != commonName {
			t.Errorf("%s: issuer wasn't correctly copied from the template. Got %s, want %s", test.name, cert.Issuer.CommonName, commonName)
		}

		if cert.SignatureAlgorithm != test.sigAlgo {
			t.Errorf("%s: SignatureAlgorithm wasn't copied from template. Got %v, want %v", test.name, cert.SignatureAlgorithm, test.sigAlgo)
		}

		if !reflect.DeepEqual(cert.ExtKeyUsage, testExtKeyUsage) {
			t.Errorf("%s: extkeyusage wasn't correctly copied from the template. Got %v, want %v", test.name, cert.ExtKeyUsage, testExtKeyUsage)
		}

		if !reflect.DeepEqual(cert.UnknownExtKeyUsage, testUnknownExtKeyUsage) {
			t.Errorf("%s: unknown extkeyusage wasn't correctly copied from the template. Got %v, want %v", test.name, cert.UnknownExtKeyUsage, testUnknownExtKeyUsage)
		}

		if !reflect.DeepEqual(cert.OCSPServer, template.OCSPServer) {
			t.Errorf("%s: OCSP servers differ from template. Got %v, want %v", test.name, cert.OCSPServer, template.OCSPServer)
		}

		if !reflect.DeepEqual(cert.IssuingCertificateURL, template.IssuingCertificateURL) {
			t.Errorf("%s: Issuing certificate URLs differ from template. Got %v, want %v", test.name, cert.IssuingCertificateURL, template.IssuingCertificateURL)
		}

		if !reflect.DeepEqual(cert.DNSNames, template.DNSNames) {
			t.Errorf("%s: SAN DNS names differ from template. Got %v, want %v", test.name, cert.DNSNames, template.DNSNames)
		}

		if !reflect.DeepEqual(cert.EmailAddresses, template.EmailAddresses) {
			t.Errorf("%s: SAN emails differ from template. Got %v, want %v", test.name, cert.EmailAddresses, template.EmailAddresses)
		}

		if len(cert.URIs) != 1 || cert.URIs[0].String() != "https://foo.com/wibble#foo" {
			t.Errorf("%s: URIs differ from template. Got %v, want %v", test.name, cert.URIs, template.URIs)
		}

		if !reflect.DeepEqual(cert.IPAddresses, template.IPAddresses) {
			t.Errorf("%s: SAN IPs differ from template. Got %v, want %v", test.name, cert.IPAddresses, template.IPAddresses)
		}

		if !reflect.DeepEqual(cert.CRLDistributionPoints, template.CRLDistributionPoints) {
			t.Errorf("%s: CRL distribution points differ from template. Got %v, want %v", test.name, cert.CRLDistributionPoints, template.CRLDistributionPoints)
		}

		if !reflect.DeepEqual(cert.SCTList, template.SCTList) {
			t.Errorf("%s: SCTList differs from template. Got %v, want %v", test.name, cert.SCTList, template.SCTList)
		}

		if !bytes.Equal(cert.SubjectKeyId, []byte{4, 3, 2, 1}) {
			t.Errorf("%s: ExtraExtensions didn't override SubjectKeyId", test.name)
		}

		if !bytes.Contains(derBytes, extraExtensionData) {
			t.Errorf("%s: didn't find extra extension in DER output", test.name)
		}

		if test.checkSig {
			err = cert.CheckSignatureFrom(cert)
			if err != nil {
				t.Errorf("%s: signature verification failed: %s", test.name, err)
			}
		}
	}
}

// Self-signed certificate using ECDSA with SHA1 & secp256r1
var ecdsaSHA1CertPem = `
-----BEGIN CERTIFICATE-----
MIICDjCCAbUCCQDF6SfN0nsnrjAJBgcqhkjOPQQBMIGPMQswCQYDVQQGEwJVUzET
MBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmlldzEVMBMG
A1UECgwMR29vZ2xlLCBJbmMuMRcwFQYDVQQDDA53d3cuZ29vZ2xlLmNvbTEjMCEG
CSqGSIb3DQEJARYUZ29sYW5nLWRldkBnbWFpbC5jb20wHhcNMTIwNTIwMjAyMDUw
WhcNMjIwNTE4MjAyMDUwWjCBjzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlm
b3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxFTATBgNVBAoMDEdvb2dsZSwg
SW5jLjEXMBUGA1UEAwwOd3d3Lmdvb2dsZS5jb20xIzAhBgkqhkiG9w0BCQEWFGdv
bGFuZy1kZXZAZ21haWwuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/Wgn
WQDo5+bz71T0327ERgd5SDDXFbXLpzIZDXTkjpe8QTEbsF+ezsQfrekrpDPC4Cd3
P9LY0tG+aI8IyVKdUjAJBgcqhkjOPQQBA0gAMEUCIGlsqMcRqWVIWTD6wXwe6Jk2
DKxL46r/FLgJYnzBEH99AiEA3fBouObsvV1R3oVkb4BQYnD4/4LeId6lAT43YvyV
a/A=
-----END CERTIFICATE-----
`

// Self-signed certificate using ECDSA with SHA256 & secp256r1
var ecdsaSHA256p256CertPem = `
-----BEGIN CERTIFICATE-----
MIICDzCCAbYCCQDlsuMWvgQzhTAKBggqhkjOPQQDAjCBjzELMAkGA1UEBhMCVVMx
EzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxFTAT
BgNVBAoMDEdvb2dsZSwgSW5jLjEXMBUGA1UEAwwOd3d3Lmdvb2dsZS5jb20xIzAh
BgkqhkiG9w0BCQEWFGdvbGFuZy1kZXZAZ21haWwuY29tMB4XDTEyMDUyMTAwMTkx
NloXDTIyMDUxOTAwMTkxNlowgY8xCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxp
Zm9ybmlhMRYwFAYDVQQHDA1Nb3VudGFpbiBWaWV3MRUwEwYDVQQKDAxHb29nbGUs
IEluYy4xFzAVBgNVBAMMDnd3dy5nb29nbGUuY29tMSMwIQYJKoZIhvcNAQkBFhRn
b2xhbmctZGV2QGdtYWlsLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPMt
2ErhxAty5EJRu9yM+MTy+hUXm3pdW1ensAv382KoGExSXAFWP7pjJnNtHO+XSwVm
YNtqjcAGFKpweoN//kQwCgYIKoZIzj0EAwIDRwAwRAIgIYSaUA/IB81gjbIw/hUV
70twxJr5EcgOo0hLp3Jm+EYCIFDO3NNcgmURbJ1kfoS3N/0O+irUtoPw38YoNkqJ
h5wi
-----END CERTIFICATE-----
`

// Self-signed certificate using ECDSA with SHA256 & secp384r1
var ecdsaSHA256p384CertPem = `
-----BEGIN CERTIFICATE-----
MIICSjCCAdECCQDje/no7mXkVzAKBggqhkjOPQQDAjCBjjELMAkGA1UEBhMCVVMx
EzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxFDAS
BgNVBAoMC0dvb2dsZSwgSW5jMRcwFQYDVQQDDA53d3cuZ29vZ2xlLmNvbTEjMCEG
CSqGSIb3DQEJARYUZ29sYW5nLWRldkBnbWFpbC5jb20wHhcNMTIwNTIxMDYxMDM0
WhcNMjIwNTE5MDYxMDM0WjCBjjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlm
b3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxFDASBgNVBAoMC0dvb2dsZSwg
SW5jMRcwFQYDVQQDDA53d3cuZ29vZ2xlLmNvbTEjMCEGCSqGSIb3DQEJARYUZ29s
YW5nLWRldkBnbWFpbC5jb20wdjAQBgcqhkjOPQIBBgUrgQQAIgNiAARRuzRNIKRK
jIktEmXanNmrTR/q/FaHXLhWRZ6nHWe26Fw7Rsrbk+VjGy4vfWtNn7xSFKrOu5ze
qxKnmE0h5E480MNgrUiRkaGO2GMJJVmxx20aqkXOk59U8yGA4CghE6MwCgYIKoZI
zj0EAwIDZwAwZAIwBZEN8gvmRmfeP/9C1PRLzODIY4JqWub2PLRT4mv9GU+yw3Gr
PU9A3CHMdEcdw/MEAjBBO1lId8KOCh9UZunsSMfqXiVurpzmhWd6VYZ/32G+M+Mh
3yILeYQzllt/g0rKVRk=
-----END CERTIFICATE-----
`

// Self-signed certificate using ECDSA with SHA384 & secp521r1
var ecdsaSHA384p521CertPem = `
-----BEGIN CERTIFICATE-----
MIICljCCAfcCCQDhp1AFD/ahKjAKBggqhkjOPQQDAzCBjjELMAkGA1UEBhMCVVMx
EzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxFDAS
BgNVBAoMC0dvb2dsZSwgSW5jMRcwFQYDVQQDDA53d3cuZ29vZ2xlLmNvbTEjMCEG
CSqGSIb3DQEJARYUZ29sYW5nLWRldkBnbWFpbC5jb20wHhcNMTIwNTIxMTUwNDI5
WhcNMjIwNTE5MTUwNDI5WjCBjjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlm
b3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxFDASBgNVBAoMC0dvb2dsZSwg
SW5jMRcwFQYDVQQDDA53d3cuZ29vZ2xlLmNvbTEjMCEGCSqGSIb3DQEJARYUZ29s
YW5nLWRldkBnbWFpbC5jb20wgZswEAYHKoZIzj0CAQYFK4EEACMDgYYABACqx9Rv
IssRs1LWYcNN+WffwlHw4Tv3y8/LIAA9MF1ZScIonU9nRMxt4a2uGJVCPDw6JHpz
PaYc0E9puLoE9AfKpwFr59Jkot7dBg55SKPEFkddoip/rvmN7NPAWjMBirOwjOkm
8FPthvPhGPqsu9AvgVuHu3PosWiHGNrhh379pva8MzAKBggqhkjOPQQDAwOBjAAw
gYgCQgEHNmswkUdPpHqrVxp9PvLVl+xxPuHBkT+75z9JizyxtqykHQo9Uh6SWCYH
BF9KLolo01wMt8DjoYP5Fb3j5MH7xwJCAbWZzTOp4l4DPkIvAh4LeC4VWbwPPyqh
kBg71w/iEcSY3wUKgHGcJJrObZw7wys91I5kENljqw/Samdr3ka+jBJa
-----END CERTIFICATE-----
`

var ecdsaTests = []struct {
	sigAlgo SignatureAlgorithm
	pemCert string
}{
	{ECDSAWithSHA1, ecdsaSHA1CertPem},
	{ECDSAWithSHA256, ecdsaSHA256p256CertPem},
	{ECDSAWithSHA256, ecdsaSHA256p384CertPem},
	{ECDSAWithSHA384, ecdsaSHA384p521CertPem},
}

func TestECDSA(t *testing.T) {
	for i, test := range ecdsaTests {
		pemBlock, _ := pem.Decode([]byte(test.pemCert))
		cert, err := ParseCertificate(pemBlock.Bytes)
		if err != nil {
			t.Errorf("%d: failed to parse certificate: %s", i, err)
			continue
		}
		if sa := cert.SignatureAlgorithm; sa != test.sigAlgo {
			t.Errorf("%d: signature algorithm is %v, want %v", i, sa, test.sigAlgo)
		}
		if parsedKey, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok {
			t.Errorf("%d: wanted an ECDSA public key but found: %#v", i, parsedKey)
		}
		if pka := cert.PublicKeyAlgorithm; pka != ECDSA {
			t.Errorf("%d: public key algorithm is %v, want ECDSA", i, pka)
		}
		if err = cert.CheckSignatureFrom(cert); err != nil {
			t.Errorf("%d: certificate verification failed: %s", i, err)
		}
	}
}

// Self-signed certificate using DSA with SHA1
var dsaCertPem = `-----BEGIN CERTIFICATE-----
MIIEDTCCA82gAwIBAgIJALHPghaoxeDhMAkGByqGSM44BAMweTELMAkGA1UEBhMC
VVMxCzAJBgNVBAgTAk5DMQ8wDQYDVQQHEwZOZXd0b24xFDASBgNVBAoTC0dvb2ds
ZSwgSW5jMRIwEAYDVQQDEwlKb24gQWxsaWUxIjAgBgkqhkiG9w0BCQEWE2pvbmFs
bGllQGdvb2dsZS5jb20wHhcNMTEwNTE0MDMwMTQ1WhcNMTEwNjEzMDMwMTQ1WjB5
MQswCQYDVQQGEwJVUzELMAkGA1UECBMCTkMxDzANBgNVBAcTBk5ld3RvbjEUMBIG
A1UEChMLR29vZ2xlLCBJbmMxEjAQBgNVBAMTCUpvbiBBbGxpZTEiMCAGCSqGSIb3
DQEJARYTam9uYWxsaWVAZ29vZ2xlLmNvbTCCAbcwggEsBgcqhkjOOAQBMIIBHwKB
gQC8hLUnQ7FpFYu4WXTj6DKvXvz8QrJkNJCVMTpKAT7uBpobk32S5RrPKXocd4gN
8lyGB9ggS03EVlEwXvSmO0DH2MQtke2jl9j1HLydClMf4sbx5V6TV9IFw505U1iW
jL7awRMgxge+FsudtJK254FjMFo03ZnOQ8ZJJ9E6AEDrlwIVAJpnBn9moyP11Ox5
Asc/5dnjb6dPAoGBAJFHd4KVv1iTVCvEG6gGiYop5DJh28hUQcN9kul+2A0yPUSC
X93oN00P8Vh3eYgSaCWZsha7zDG53MrVJ0Zf6v/X/CoZNhLldeNOepivTRAzn+Rz
kKUYy5l1sxYLHQKF0UGNCXfFKZT0PCmgU+PWhYNBBMn6/cIh44vp85ideo5CA4GE
AAKBgFmifCafzeRaohYKXJgMGSEaggCVCRq5xdyDCat+wbOkjC4mfG01/um3G8u5
LxasjlWRKTR/tcAL7t0QuokVyQaYdVypZXNaMtx1db7YBuHjj3aP+8JOQRI9xz8c
bp5NDJ5pISiFOv4p3GZfqZPcqckDt78AtkQrmnal2txhhjF6o4HeMIHbMB0GA1Ud
DgQWBBQVyyr7hO11ZFFpWX50298Sa3V+rzCBqwYDVR0jBIGjMIGggBQVyyr7hO11
ZFFpWX50298Sa3V+r6F9pHsweTELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAk5DMQ8w
DQYDVQQHEwZOZXd0b24xFDASBgNVBAoTC0dvb2dsZSwgSW5jMRIwEAYDVQQDEwlK
b24gQWxsaWUxIjAgBgkqhkiG9w0BCQEWE2pvbmFsbGllQGdvb2dsZS5jb22CCQCx
z4IWqMXg4TAMBgNVHRMEBTADAQH/MAkGByqGSM44BAMDLwAwLAIUPtn/5j8Q1jJI
7ggOIsgrhgUdjGQCFCsmDq1H11q9+9Wp9IMeGrTSKHIM
-----END CERTIFICATE-----
`

func TestParseCertificateWithDsaPublicKey(t *testing.T) {
	expectedKey := &dsa.PublicKey{
		Parameters: dsa.Parameters{
			P: bigFromHexString("00BC84B52743B169158BB85974E3E832AF5EFCFC42B264349095313A4A013EEE069A1B937D92E51ACF297A1C77880DF25C8607D8204B4DC45651305EF4A63B40C7D8C42D91EDA397D8F51CBC9D0A531FE2C6F1E55E9357D205C39D395358968CBEDAC11320C607BE16CB9DB492B6E78163305A34DD99CE43C64927D13A0040EB97"),
			Q: bigFromHexString("009A67067F66A323F5D4EC7902C73FE5D9E36FA74F"),
			G: bigFromHexString("009147778295BF5893542BC41BA806898A29E43261DBC85441C37D92E97ED80D323D44825FDDE8374D0FF15877798812682599B216BBCC31B9DCCAD527465FEAFFD7FC2A193612E575E34E7A98AF4D10339FE47390A518CB9975B3160B1D0285D1418D0977C52994F43C29A053E3D685834104C9FAFDC221E38BE9F3989D7A8E42"),
		},
		Y: bigFromHexString("59A27C269FCDE45AA2160A5C980C19211A820095091AB9C5DC8309AB7EC1B3A48C2E267C6D35FEE9B71BCBB92F16AC8E559129347FB5C00BEEDD10BA8915C90698755CA965735A32DC7575BED806E1E38F768FFBC24E41123DC73F1C6E9E4D0C9E692128853AFE29DC665FA993DCA9C903B7BF00B6442B9A76A5DADC6186317A"),
	}
	pemBlock, _ := pem.Decode([]byte(dsaCertPem))
	cert, err := ParseCertificate(pemBlock.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %s", err)
	}
	if cert.PublicKeyAlgorithm != DSA {
		t.Errorf("Parsed key algorithm was not DSA")
	}
	parsedKey, ok := cert.PublicKey.(*dsa.PublicKey)
	if !ok {
		t.Fatalf("Parsed key was not a DSA key: %s", err)
	}
	if expectedKey.Y.Cmp(parsedKey.Y) != 0 ||
		expectedKey.P.Cmp(parsedKey.P) != 0 ||
		expectedKey.Q.Cmp(parsedKey.Q) != 0 ||
		expectedKey.G.Cmp(parsedKey.G) != 0 {
		t.Fatal("Parsed key differs from expected key")
	}
}

func TestParseCertificateWithDSASignatureAlgorithm(t *testing.T) {
	pemBlock, _ := pem.Decode([]byte(dsaCertPem))
	cert, err := ParseCertificate(pemBlock.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %s", err)
	}
	if cert.SignatureAlgorithm != DSAWithSHA1 {
		t.Errorf("Parsed signature algorithm was not DSAWithSHA1")
	}
}

func TestVerifyCertificateWithDSASignature(t *testing.T) {
	pemBlock, _ := pem.Decode([]byte(dsaCertPem))
	cert, err := ParseCertificate(pemBlock.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %s", err)
	}
	// test cert is self-signed
	if err = cert.CheckSignatureFrom(cert); err != nil {
		t.Fatalf("DSA Certificate verification failed: %s", err)
	}
}

var rsaPSSSelfSignedPEM = `-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----`

func TestRSAPSSSelfSigned(t *testing.T) {
	der, _ := pem.Decode([]byte(rsaPSSSelfSignedPEM))
	if der == nil {
		t.Fatal("Failed to find PEM block")
	}

	cert, err := ParseCertificate(der.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	if err = cert.CheckSignatureFrom(cert); err != nil {
		t.Fatal(err)
	}
}

const (
	pemCertificate = `-----BEGIN CERTIFICATE-----
MIIDATCCAemgAwIBAgIRAKQkkrFx1T/dgB/Go/xBM5swDQYJKoZIhvcNAQELBQAw
EjEQMA4GA1UEChMHQWNtZSBDbzAeFw0xNjA4MTcyMDM2MDdaFw0xNzA4MTcyMDM2
MDdaMBIxEDAOBgNVBAoTB0FjbWUgQ28wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDAoJtjG7M6InsWwIo+l3qq9u+g2rKFXNu9/mZ24XQ8XhV6PUR+5HQ4
jUFWC58ExYhottqK5zQtKGkw5NuhjowFUgWB/VlNGAUBHtJcWR/062wYrHBYRxJH
qVXOpYKbIWwFKoXu3hcpg/CkdOlDWGKoZKBCwQwUBhWE7MDhpVdQ+ZljUJWL+FlK
yQK5iRsJd5TGJ6VUzLzdT4fmN2DzeK6GLeyMpVpU3sWV90JJbxWQ4YrzkKzYhMmB
EcpXTG2wm+ujiHU/k2p8zlf8Sm7VBM/scmnMFt0ynNXop4FWvJzEm1G0xD2t+e2I
5Utr04dOZPCgkm++QJgYhtZvgW7ZZiGTAgMBAAGjUjBQMA4GA1UdDwEB/wQEAwIF
oDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMBsGA1UdEQQUMBKC
EHRlc3QuZXhhbXBsZS5jb20wDQYJKoZIhvcNAQELBQADggEBADpqKQxrthH5InC7
X96UP0OJCu/lLEMkrjoEWYIQaFl7uLPxKH5AmQPH4lYwF7u7gksR7owVG9QU9fs6
1fK7II9CVgCd/4tZ0zm98FmU4D0lHGtPARrrzoZaqVZcAvRnFTlPX5pFkPhVjjai
/mkxX9LpD8oK1445DFHxK5UjLMmPIIWd8EOi+v5a+hgGwnJpoW7hntSl8kHMtTmy
fnnktsblSUV4lRCit0ymC7Ojhe+gzCCwkgs5kDzVVag+tnl/0e2DloIjASwOhpbH
KVcg7fBd484ht/sS+l0dsB4KDOSpd8JzVDMF8OZqlaydizoJO0yWr9GbCN1+OKq5
EhLrEqU=
-----END CERTIFICATE-----`
	pemPrecertificate = `-----BEGIN CERTIFICATE-----
MIIC3zCCAkigAwIBAgIBBzANBgkqhkiG9w0BAQUFADBVMQswCQYDVQQGEwJHQjEk
MCIGA1UEChMbQ2VydGlmaWNhdGUgVHJhbnNwYXJlbmN5IENBMQ4wDAYDVQQIEwVX
YWxlczEQMA4GA1UEBxMHRXJ3IFdlbjAeFw0xMjA2MDEwMDAwMDBaFw0yMjA2MDEw
MDAwMDBaMFIxCzAJBgNVBAYTAkdCMSEwHwYDVQQKExhDZXJ0aWZpY2F0ZSBUcmFu
c3BhcmVuY3kxDjAMBgNVBAgTBVdhbGVzMRAwDgYDVQQHEwdFcncgV2VuMIGfMA0G
CSqGSIb3DQEBAQUAA4GNADCBiQKBgQC+75jnwmh3rjhfdTJaDB0ym+3xj6r015a/
BH634c4VyVui+A7kWL19uG+KSyUhkaeb1wDDjpwDibRc1NyaEgqyHgy0HNDnKAWk
EM2cW9tdSSdyba8XEPYBhzd+olsaHjnu0LiBGdwVTcaPfajjDK8VijPmyVCfSgWw
FAn/Xdh+tQIDAQABo4HBMIG+MB0GA1UdDgQWBBQgMVQa8lwF/9hli2hDeU9ekDb3
tDB9BgNVHSMEdjB0gBRfnYgNyHPmVNT4DdjmsMEktEfDVaFZpFcwVTELMAkGA1UE
BhMCR0IxJDAiBgNVBAoTG0NlcnRpZmljYXRlIFRyYW5zcGFyZW5jeSBDQTEOMAwG
A1UECBMFV2FsZXMxEDAOBgNVBAcTB0VydyBXZW6CAQAwCQYDVR0TBAIwADATBgor
BgEEAdZ5AgQDAQH/BAIFADANBgkqhkiG9w0BAQUFAAOBgQACocOeAVr1Tf8CPDNg
h1//NDdVLx8JAb3CVDFfM3K3I/sV+87MTfRxoM5NjFRlXYSHl/soHj36u0YtLGhL
BW/qe2O0cP8WbjLURgY1s9K8bagkmyYw5x/DTwjyPdTuIo+PdPY9eGMR3QpYEUBf
kGzKLC0+6/yBmWTr2M98CIY/vg==
-----END CERTIFICATE-----`
)

func TestIsPrecertificate(t *testing.T) {
	tests := []struct {
		desc    string
		certPEM string
		want    bool
	}{
		{
			desc:    "certificate",
			certPEM: pemCertificate,
			want:    false,
		},
		{
			desc:    "precertificate",
			certPEM: pemPrecertificate,
			want:    true,
		},
		{
			desc:    "nil",
			certPEM: "",
			want:    false,
		},
	}

	for _, test := range tests {
		var cert *Certificate
		if test.certPEM != "" {
			var err error
			cert, err = certificateFromPEM(test.certPEM)
			if err != nil {
				t.Errorf("%s: error parsing certificate: %s", test.desc, err)
				continue
			}
		}
		if got := cert.IsPrecertificate(); got != test.want {
			t.Errorf("%s: c.IsPrecertificate() = %t, want %t", test.desc, got, test.want)
		}
	}
}

func TestCRLCreation(t *testing.T) {
	block, _ := pem.Decode([]byte(pemPrivateKey))
	priv, _ := ParsePKCS1PrivateKey(block.Bytes)
	block, _ = pem.Decode([]byte(pemCertificate))
	cert, _ := ParseCertificate(block.Bytes)

	loc := time.FixedZone("Oz/Atlantis", int((2 * time.Hour).Seconds()))

	now := time.Unix(1000, 0).In(loc)
	nowUTC := now.UTC()
	expiry := time.Unix(10000, 0)

	revokedCerts := []pkix.RevokedCertificate{
		{
			SerialNumber:   big.NewInt(1),
			RevocationTime: nowUTC,
		},
		{
			SerialNumber: big.NewInt(42),
			// RevocationTime should be converted to UTC before marshaling.
			RevocationTime: now,
		},
	}
	expectedCerts := []pkix.RevokedCertificate{
		{
			SerialNumber:   big.NewInt(1),
			RevocationTime: nowUTC,
		},
		{
			SerialNumber:   big.NewInt(42),
			RevocationTime: nowUTC,
		},
	}

	crlBytes, err := cert.CreateCRL(rand.Reader, priv, revokedCerts, now, expiry)
	if err != nil {
		t.Errorf("error creating CRL: %s", err)
	}

	parsedCRL, err := ParseDERCRL(crlBytes)
	if err != nil {
		t.Errorf("error reparsing CRL: %s", err)
	}
	if !reflect.DeepEqual(parsedCRL.TBSCertList.RevokedCertificates, expectedCerts) {
		t.Errorf("RevokedCertificates mismatch: got %v; want %v.",
			parsedCRL.TBSCertList.RevokedCertificates, expectedCerts)
	}
}

func fromBase64(in string) []byte {
	out := make([]byte, base64.StdEncoding.DecodedLen(len(in)))
	n, err := base64.StdEncoding.Decode(out, []byte(in))
	if err != nil {
		panic("failed to base64 decode")
	}
	return out[:n]
}

func TestParseDERCRL(t *testing.T) {
	derBytes := fromBase64(derCRLBase64)
	certList, err := ParseDERCRL(derBytes)
	if err != nil {
		t.Errorf("error parsing: %s", err)
		return
	}
	numCerts := len(certList.TBSCertList.RevokedCertificates)
	expected := 88
	if numCerts != expected {
		t.Errorf("bad number of revoked certificates. got: %d want: %d", numCerts, expected)
	}

	if certList.HasExpired(time.Unix(1302517272, 0)) {
		t.Errorf("CRL has expired (but shouldn't have)")
	}

	// Can't check the signature here without a package cycle.
}

func TestCRLWithoutExpiry(t *testing.T) {
	derBytes := fromBase64("MIHYMIGZMAkGByqGSM44BAMwEjEQMA4GA1UEAxMHQ2FybERTUxcNOTkwODI3MDcwMDAwWjBpMBMCAgDIFw05OTA4MjIwNzAwMDBaMBMCAgDJFw05OTA4MjIwNzAwMDBaMBMCAgDTFw05OTA4MjIwNzAwMDBaMBMCAgDSFw05OTA4MjIwNzAwMDBaMBMCAgDUFw05OTA4MjQwNzAwMDBaMAkGByqGSM44BAMDLwAwLAIUfmVSdjP+NHMX0feW+aDU2G1cfT0CFAJ6W7fVWxjBz4fvftok8yqDnDWh")
	certList, err := ParseDERCRL(derBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !certList.TBSCertList.NextUpdate.IsZero() {
		t.Errorf("NextUpdate is not the zero value")
	}
}

func TestParsePEMCRL(t *testing.T) {
	pemBytes := fromBase64(pemCRLBase64)
	certList, err := ParseCRL(pemBytes)
	if err != nil {
		t.Errorf("error parsing: %s", err)
		return
	}
	numCerts := len(certList.TBSCertList.RevokedCertificates)
	expected := 2
	if numCerts != expected {
		t.Errorf("bad number of revoked certificates. got: %d want: %d", numCerts, expected)
	}

	if certList.HasExpired(time.Unix(1302517272, 0)) {
		t.Errorf("CRL has expired (but shouldn't have)")
	}

	// Can't check the signature here without a package cycle.
}

func TestNonFatalErrors(t *testing.T) {
	nfe := NonFatalErrors{}

	nfe.AddError(errors.New("one"))
	nfe.AddError(errors.New("two"))
	nfe.AddError(errors.New("three"))

	if !nfe.HasError() {
		t.Fatal("NonFatalError claimed not to have an error")
	}

	if !strings.Contains(nfe.Error(), "one; two; three") {
		t.Fatalf("Didn't see expected string from Error(), got '%s'", nfe.Error())
	}
}

func TestIsFatal(t *testing.T) {
	tests := []struct {
		err  error
		want bool
	}{
		{err: errors.New("normal error"), want: true},
		{err: NonFatalErrors{}, want: false},
		{err: nil, want: false},
		{err: &Errors{}, want: false},
		{err: &Errors{Errs: []Error{{ID: 1, Summary: "test", Fatal: true}}}, want: true},
		{err: &Errors{Errs: []Error{{ID: 1, Summary: "test", Fatal: false}}}, want: false},
	}
	for _, test := range tests {
		got := IsFatal(test.err)
		if got != test.want {
			t.Errorf("IsFatal(%T %v)=%v, want %v", test.err, test.err, got, test.want)
		}
	}
}

const (
	tbsNoPoison = "30820245a003020102020842822a5b866fbfeb300d06092a864886f70d01010b" +
		"05003071310b3009060355040613024742310f300d060355040813064c6f6e64" +
		"6f6e310f300d060355040713064c6f6e646f6e310f300d060355040a1306476f" +
		"6f676c65310c300a060355040b1303456e673121301f0603550403131846616b" +
		"654365727469666963617465417574686f72697479301e170d31363037313731" +
		"31313534305a170d3139303331393131313534305a3066310b30090603550406" +
		"130255533113301106035504080c0a43616c69666f726e696131163014060355" +
		"04070c0d4d6f756e7461696e205669657731133011060355040a0c0a476f6f67" +
		"6c6520496e633115301306035504030c0c2a2e676f6f676c652e636f6d305930" +
		"1306072a8648ce3d020106082a8648ce3d03010703420004c4093984f5158d12" +
		"54b2029cf901e26d3547d40dd011616609351dcb121495b23fff35bd228e4dfc" +
		"38502d22d6981ecaa023afa4967e32d1825f3157fb28ff37a381ce3081cb301d" +
		"0603551d250416301406082b0601050507030106082b06010505070302306806" +
		"082b06010505070101045c305a302b06082b06010505073002861f687474703a" +
		"2f2f706b692e676f6f676c652e636f6d2f47494147322e637274302b06082b06" +
		"010505073001861f687474703a2f2f636c69656e7473312e676f6f676c652e63" +
		"6f6d2f6f637370301d0603551d0e04160414dbf46e63eee2dcbebf38604f9831" +
		"d06444f163d830210603551d20041a3018300c060a2b06010401d67902050130" +
		"08060667810c010202"
	tbsPoisonFirst = "3082025aa003020102020842822a5b866fbfeb300d06092a864886f70d01010b" +
		"05003071310b3009060355040613024742310f300d060355040813064c6f6e64" +
		"6f6e310f300d060355040713064c6f6e646f6e310f300d060355040a1306476f" +
		"6f676c65310c300a060355040b1303456e673121301f0603550403131846616b" +
		"654365727469666963617465417574686f72697479301e170d31363037313731" +
		"31313534305a170d3139303331393131313534305a3066310b30090603550406" +
		"130255533113301106035504080c0a43616c69666f726e696131163014060355" +
		"04070c0d4d6f756e7461696e205669657731133011060355040a0c0a476f6f67" +
		"6c6520496e633115301306035504030c0c2a2e676f6f676c652e636f6d305930" +
		"1306072a8648ce3d020106082a8648ce3d03010703420004c4093984f5158d12" +
		"54b2029cf901e26d3547d40dd011616609351dcb121495b23fff35bd228e4dfc" +
		"38502d22d6981ecaa023afa4967e32d1825f3157fb28ff37a381e33081e03013" +
		"060a2b06010401d6790204030101ff04020500301d0603551d25041630140608" +
		"2b0601050507030106082b06010505070302306806082b06010505070101045c" +
		"305a302b06082b06010505073002861f687474703a2f2f706b692e676f6f676c" +
		"652e636f6d2f47494147322e637274302b06082b06010505073001861f687474" +
		"703a2f2f636c69656e7473312e676f6f676c652e636f6d2f6f637370301d0603" +
		"551d0e04160414dbf46e63eee2dcbebf38604f9831d06444f163d83021060355" +
		"1d20041a3018300c060a2b06010401d6790205013008060667810c010202"
	tbsPoisonLast = "3082025aa003020102020842822a5b866fbfeb300d06092a864886f70d01010b" +
		"05003071310b3009060355040613024742310f300d060355040813064c6f6e64" +
		"6f6e310f300d060355040713064c6f6e646f6e310f300d060355040a1306476f" +
		"6f676c65310c300a060355040b1303456e673121301f0603550403131846616b" +
		"654365727469666963617465417574686f72697479301e170d31363037313731" +
		"31313534305a170d3139303331393131313534305a3066310b30090603550406" +
		"130255533113301106035504080c0a43616c69666f726e696131163014060355" +
		"04070c0d4d6f756e7461696e205669657731133011060355040a0c0a476f6f67" +
		"6c6520496e633115301306035504030c0c2a2e676f6f676c652e636f6d305930" +
		"1306072a8648ce3d020106082a8648ce3d03010703420004c4093984f5158d12" +
		"54b2029cf901e26d3547d40dd011616609351dcb121495b23fff35bd228e4dfc" +
		"38502d22d6981ecaa023afa4967e32d1825f3157fb28ff37a381e33081e0301d" +
		"0603551d250416301406082b0601050507030106082b06010505070302306806" +
		"082b06010505070101045c305a302b06082b06010505073002861f687474703a" +
		"2f2f706b692e676f6f676c652e636f6d2f47494147322e637274302b06082b06" +
		"010505073001861f687474703a2f2f636c69656e7473312e676f6f676c652e63" +
		"6f6d2f6f637370301d0603551d0e04160414dbf46e63eee2dcbebf38604f9831" +
		"d06444f163d830210603551d20041a3018300c060a2b06010401d67902050130" +
		"08060667810c0102023013060a2b06010401d6790204030101ff04020500"
	tbsPoisonMiddle = "3082025aa003020102020842822a5b866fbfeb300d06092a864886f70d01010b" +
		"05003071310b3009060355040613024742310f300d060355040813064c6f6e64" +
		"6f6e310f300d060355040713064c6f6e646f6e310f300d060355040a1306476f" +
		"6f676c65310c300a060355040b1303456e673121301f0603550403131846616b" +
		"654365727469666963617465417574686f72697479301e170d31363037313731" +
		"31313534305a170d3139303331393131313534305a3066310b30090603550406" +
		"130255533113301106035504080c0a43616c69666f726e696131163014060355" +
		"04070c0d4d6f756e7461696e205669657731133011060355040a0c0a476f6f67" +
		"6c6520496e633115301306035504030c0c2a2e676f6f676c652e636f6d305930" +
		"1306072a8648ce3d020106082a8648ce3d03010703420004c4093984f5158d12" +
		"54b2029cf901e26d3547d40dd011616609351dcb121495b23fff35bd228e4dfc" +
		"38502d22d6981ecaa023afa4967e32d1825f3157fb28ff37a381e33081e0301d" +
		"0603551d250416301406082b0601050507030106082b06010505070302306806" +
		"082b06010505070101045c305a302b06082b06010505073002861f687474703a" +
		"2f2f706b692e676f6f676c652e636f6d2f47494147322e637274302b06082b06" +
		"010505073001861f687474703a2f2f636c69656e7473312e676f6f676c652e63" +
		"6f6d2f6f6373703013060a2b06010401d6790204030101ff04020500301d0603" +
		"551d0e04160414dbf46e63eee2dcbebf38604f9831d06444f163d83021060355" +
		"1d20041a3018300c060a2b06010401d6790205013008060667810c010202"
	tbsPoisonTwice = "3082026fa003020102020842822a5b866fbfeb300d06092a864886f70d01010b" +
		"05003071310b3009060355040613024742310f300d060355040813064c6f6e64" +
		"6f6e310f300d060355040713064c6f6e646f6e310f300d060355040a1306476f" +
		"6f676c65310c300a060355040b1303456e673121301f0603550403131846616b" +
		"654365727469666963617465417574686f72697479301e170d31363037313731" +
		"31313534305a170d3139303331393131313534305a3066310b30090603550406" +
		"130255533113301106035504080c0a43616c69666f726e696131163014060355" +
		"04070c0d4d6f756e7461696e205669657731133011060355040a0c0a476f6f67" +
		"6c6520496e633115301306035504030c0c2a2e676f6f676c652e636f6d305930" +
		"1306072a8648ce3d020106082a8648ce3d03010703420004c4093984f5158d12" +
		"54b2029cf901e26d3547d40dd011616609351dcb121495b23fff35bd228e4dfc" +
		"38502d22d6981ecaa023afa4967e32d1825f3157fb28ff37a381f83081f5301d" +
		"0603551d250416301406082b0601050507030106082b06010505070302306806" +
		"082b06010505070101045c305a302b06082b06010505073002861f687474703a" +
		"2f2f706b692e676f6f676c652e636f6d2f47494147322e637274302b06082b06" +
		"010505073001861f687474703a2f2f636c69656e7473312e676f6f676c652e63" +
		"6f6d2f6f6373703013060a2b06010401d6790204030101ff04020500301d0603" +
		"551d0e04160414dbf46e63eee2dcbebf38604f9831d06444f163d83013060a2b" +
		"06010401d6790204030101ff0402050030210603551d20041a3018300c060a2b" +
		"06010401d6790205013008060667810c010202"
)

func TestRemoveCTPoison(t *testing.T) {
	var tests = []struct {
		name   string // for human consumption
		tbs    string // hex encoded
		want   string // hex encoded
		errstr string
	}{
		{name: "invalid-der", tbs: "01020304", errstr: "failed to parse"},
		{name: "trailing-data", tbs: tbsPoisonMiddle + "01020304", errstr: "trailing data"},
		{name: "no-poison-ext", tbs: tbsNoPoison, errstr: "no extension of specified type present"},
		{name: "two-poison-exts", tbs: tbsPoisonTwice, errstr: "multiple extensions of specified type present"},
		{name: "poison-first", tbs: tbsPoisonFirst, want: tbsNoPoison},
		{name: "poison-last", tbs: tbsPoisonLast, want: tbsNoPoison},
		{name: "poison-middle", tbs: tbsPoisonMiddle, want: tbsNoPoison},
	}
	for _, test := range tests {
		in, _ := hex.DecodeString(test.tbs)
		got, err := RemoveCTPoison(in)
		if test.errstr != "" {
			if err == nil {
				t.Errorf("RemoveCTPoison(%s)=%s,nil; want error %q", test.name, hex.EncodeToString(got), test.errstr)
			} else if !strings.Contains(err.Error(), test.errstr) {
				t.Errorf("RemoveCTPoison(%s)=nil,%q; want error %q", test.name, err, test.errstr)
			}
			continue
		}
		want, _ := hex.DecodeString(test.want)
		if err != nil {
			t.Errorf("RemoveCTPoison(%s)=nil,%q; want %s,nil", test.name, err, test.want)
		} else if !bytes.Equal(got, want) {
			t.Errorf("RemoveCTPoison(%s)=%s,nil; want %s,nil", test.name, hex.EncodeToString(got), test.want)
		}
	}
}

func makeCert(t *testing.T, template, issuer *Certificate) *Certificate {
	t.Helper()
	certData, err := CreateCertificate(rand.Reader, template, issuer, &testPrivateKey.PublicKey, testPrivateKey)
	if err != nil {
		t.Fatalf("failed to create pre-cert: %v", err)
	}
	cert, err := ParseCertificate(certData)
	if err != nil {
		t.Fatalf("failed to re-parse pre-cert: %v", err)
	}
	return cert
}

func TestBuildPrecertTBS(t *testing.T) {
	poisonExt := pkix.Extension{Id: OIDExtensionCTPoison, Critical: true, Value: asn1.NullBytes}
	preIssuerKeyID := []byte{0x19, 0x09, 0x19, 0x70}
	issuerKeyID := []byte{0x07, 0x07, 0x20, 0x07}
	preCertTemplate := Certificate{
		Version:         3,
		SerialNumber:    big.NewInt(123),
		Issuer:          pkix.Name{CommonName: "precert Issuer"},
		Subject:         pkix.Name{CommonName: "precert subject"},
		NotBefore:       time.Now(),
		NotAfter:        time.Now().Add(3 * time.Hour),
		ExtraExtensions: []pkix.Extension{poisonExt},
		AuthorityKeyId:  preIssuerKeyID,
	}
	preIssuerTemplate := Certificate{
		Version:        3,
		SerialNumber:   big.NewInt(1234),
		Issuer:         pkix.Name{CommonName: "real Issuer"},
		Subject:        pkix.Name{CommonName: "precert Issuer"},
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(3 * time.Hour),
		AuthorityKeyId: issuerKeyID,
		SubjectKeyId:   preIssuerKeyID,
		ExtKeyUsage:    []ExtKeyUsage{ExtKeyUsageCertificateTransparency},
	}
	actualIssuerTemplate := Certificate{
		Version:      3,
		SerialNumber: big.NewInt(12345),
		Issuer:       pkix.Name{CommonName: "real Issuer"},
		Subject:      pkix.Name{CommonName: "real Issuer"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(3 * time.Hour),
		SubjectKeyId: issuerKeyID,
	}
	preCertWithAKI := makeCert(t, &preCertTemplate, &preIssuerTemplate)
	preIssuerWithAKI := makeCert(t, &preIssuerTemplate, &actualIssuerTemplate)

	preIssuerTemplate.AuthorityKeyId = nil
	actualIssuerTemplate.SubjectKeyId = nil
	preIssuerWithoutAKI := makeCert(t, &preIssuerTemplate, &actualIssuerTemplate)

	preCertTemplate.AuthorityKeyId = nil
	preIssuerTemplate.SubjectKeyId = nil
	preCertWithoutAKI := makeCert(t, &preCertTemplate, &preIssuerTemplate)

	preIssuerTemplate.ExtKeyUsage = nil
	invalidPreIssuer := makeCert(t, &preIssuerTemplate, &actualIssuerTemplate)

	akiPrefix := []byte{0x30, 0x06, 0x80, 0x04} // SEQUENCE { [0] { ... } }
	var tests = []struct {
		name      string
		tbs       *Certificate
		preIssuer *Certificate
		wantAKI   []byte
		wantErr   bool
	}{
		{
			name:    "no-preIssuer-provided",
			tbs:     preCertWithAKI,
			wantAKI: append(akiPrefix, preIssuerKeyID...),
		},
		{
			name:      "both-with-AKI",
			tbs:       preCertWithAKI,
			preIssuer: preIssuerWithAKI,
			wantAKI:   append(akiPrefix, issuerKeyID...),
		},
		{
			name:      "invalid-preIssuer",
			tbs:       preCertWithAKI,
			preIssuer: invalidPreIssuer,
			wantErr:   true,
		},
		{
			name:      "both-without-AKI",
			tbs:       preCertWithoutAKI,
			preIssuer: preIssuerWithoutAKI,
		},
		{
			name:      "precert-with-preIssuer-without-AKI",
			tbs:       preCertWithAKI,
			preIssuer: preIssuerWithoutAKI,
		},
		{
			name:      "precert-without-preIssuer-with-AKI",
			tbs:       preCertWithoutAKI,
			preIssuer: preIssuerWithAKI,
			wantAKI:   append(akiPrefix, issuerKeyID...),
		},
	}
	for _, test := range tests {
		got, err := BuildPrecertTBS(test.tbs.RawTBSCertificate, test.preIssuer)
		if err != nil {
			if !test.wantErr {
				t.Errorf("BuildPrecertTBS(%s)=nil,%q; want _,nil", test.name, err)
			}
			continue
		}
		if test.wantErr {
			t.Errorf("BuildPrecertTBS(%s)=_,nil; want _,non-nil", test.name)
		}

		var tbs tbsCertificate
		if rest, err := asn1.Unmarshal(got, &tbs); err != nil {
			t.Errorf("BuildPrecertTBS(%s) gave unparsable TBS: %v", test.name, err)
			continue
		} else if len(rest) > 0 {
			t.Errorf("BuildPrecertTBS(%s) gave extra data in DER", test.name)
		}
		if test.preIssuer != nil {
			if got, want := tbs.Issuer.FullBytes, test.preIssuer.RawIssuer; !bytes.Equal(got, want) {
				t.Errorf("BuildPrecertTBS(%s).Issuer=%x, want %x", test.name, got, want)
			}
		}
		var gotAKI []byte
		for _, ext := range tbs.Extensions {
			if ext.Id.Equal(OIDExtensionAuthorityKeyId) {
				gotAKI = ext.Value
				break
			}
		}
		if gotAKI != nil {
			if test.wantAKI != nil {
				if !reflect.DeepEqual(gotAKI, test.wantAKI) {
					t.Errorf("BuildPrecertTBS(%s).Extensions[AKI]=%+v, want %+v", test.name, gotAKI, test.wantAKI)
				}
			} else {
				t.Errorf("BuildPrecertTBS(%s).Extensions[AKI]=%+v, want nil", test.name, gotAKI)
			}
		} else if test.wantAKI != nil {
			t.Errorf("BuildPrecertTBS(%s).Extensions[AKI]=nil, want %+v", test.name, test.wantAKI)
		}
	}
}

func TestImports(t *testing.T) {
	//	testenv.MustHaveGoRun(t)

	// Replace testenv.GoToolPath(t) with "go" for use outside of Go repo.
	if err := exec.Command("go", "run", "x509_test_import.go").Run(); err != nil {
		t.Errorf("failed to run x509_test_import.go: %s", err)
	}
}

const derCRLBase64 = "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"

const pemCRLBase64 = "LS0tLS1CRUdJTiBYNTA5IENSTC0tLS0tDQpNSUlCOWpDQ0FWOENBUUV3RFFZSktvWklodmNOQVFFRkJRQXdiREVhTUJnR0ExVUVDaE1SVWxOQklGTmxZM1Z5DQphWFI1SUVsdVl5NHhIakFjQmdOVkJBTVRGVkpUUVNCUWRXSnNhV01nVW05dmRDQkRRU0IyTVRFdU1Dd0dDU3FHDQpTSWIzRFFFSkFSWWZjbk5oYTJWdmJuSnZiM1J6YVdkdVFISnpZWE5sWTNWeWFYUjVMbU52YlJjTk1URXdNakl6DQpNVGt5T0RNd1doY05NVEV3T0RJeU1Ua3lPRE13V2pDQmpEQktBaEVBckRxb2g5RkhKSFhUN09QZ3V1bjQrQmNODQpNRGt4TVRBeU1UUXlOekE1V2pBbU1Bb0dBMVVkRlFRRENnRUpNQmdHQTFVZEdBUVJHQTh5TURBNU1URXdNakUwDQpNalExTlZvd1BnSVJBTEd6blowOTVQQjVhQU9MUGc1N2ZNTVhEVEF5TVRBeU16RTBOVEF4TkZvd0dqQVlCZ05WDQpIUmdFRVJnUE1qQXdNakV3TWpNeE5EVXdNVFJhb0RBd0xqQWZCZ05WSFNNRUdEQVdnQlQxVERGNlVRTS9MTmVMDQpsNWx2cUhHUXEzZzltekFMQmdOVkhSUUVCQUlDQUlRd0RRWUpLb1pJaHZjTkFRRUZCUUFEZ1lFQUZVNUFzNk16DQpxNVBSc2lmYW9iUVBHaDFhSkx5QytNczVBZ2MwYld5QTNHQWR4dXI1U3BQWmVSV0NCamlQL01FSEJXSkNsQkhQDQpHUmNxNXlJZDNFakRrYUV5eFJhK2k2N0x6dmhJNmMyOUVlNks5cFNZd2ppLzdSVWhtbW5Qclh0VHhsTDBsckxyDQptUVFKNnhoRFJhNUczUUE0Q21VZHNITnZicnpnbUNZcHZWRT0NCi0tLS0tRU5EIFg1MDkgQ1JMLS0tLS0NCg0K"

func TestCreateCertificateRequest(t *testing.T) {
	random := rand.Reader

	ecdsa256Priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %s", err)
	}

	ecdsa384Priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %s", err)
	}

	ecdsa521Priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %s", err)
	}

	tests := []struct {
		name    string
		priv    interface{}
		sigAlgo SignatureAlgorithm
	}{
		{"RSA", testPrivateKey, SHA1WithRSA},
		{"ECDSA-256", ecdsa256Priv, ECDSAWithSHA1},
		{"ECDSA-384", ecdsa384Priv, ECDSAWithSHA1},
		{"ECDSA-521", ecdsa521Priv, ECDSAWithSHA1},
	}

	for _, test := range tests {
		template := CertificateRequest{
			Subject: pkix.Name{
				CommonName:   "test.example.com",
				Organization: []string{"Σ Acme Co"},
			},
			SignatureAlgorithm: test.sigAlgo,
			DNSNames:           []string{"test.example.com"},
			EmailAddresses:     []string{"gopher@golang.org"},
			IPAddresses:        []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},
		}

		derBytes, err := CreateCertificateRequest(random, &template, test.priv)
		if err != nil {
			t.Errorf("%s: failed to create certificate request: %s", test.name, err)
			continue
		}

		out, err := ParseCertificateRequest(derBytes)
		if err != nil {
			t.Errorf("%s: failed to create certificate request: %s", test.name, err)
			continue
		}

		err = out.CheckSignature()
		if err != nil {
			t.Errorf("%s: failed to check certificate request signature: %s", test.name, err)
			continue
		}

		if out.Subject.CommonName != template.Subject.CommonName {
			t.Errorf("%s: output subject common name and template subject common name don't match", test.name)
		} else if len(out.Subject.Organization) != len(template.Subject.Organization) {
			t.Errorf("%s: output subject organisation and template subject organisation don't match", test.name)
		} else if len(out.DNSNames) != len(template.DNSNames) {
			t.Errorf("%s: output DNS names and template DNS names don't match", test.name)
		} else if len(out.EmailAddresses) != len(template.EmailAddresses) {
			t.Errorf("%s: output email addresses and template email addresses don't match", test.name)
		} else if len(out.IPAddresses) != len(template.IPAddresses) {
			t.Errorf("%s: output IP addresses and template IP addresses names don't match", test.name)
		}
	}
}

func marshalAndParseCSR(t *testing.T, template *CertificateRequest) *CertificateRequest {
	derBytes, err := CreateCertificateRequest(rand.Reader, template, testPrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	csr, err := ParseCertificateRequest(derBytes)
	if err != nil {
		t.Fatal(err)
	}

	return csr
}

func TestCertificateRequestOverrides(t *testing.T) {
	sanContents, err := marshalSANs([]string{"foo.example.com"}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	template := CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Σ Acme Co"},
		},
		DNSNames: []string{"test.example.com"},

		// An explicit extension should override the DNSNames from the
		// template.
		ExtraExtensions: []pkix.Extension{
			{
				Id:    OIDExtensionSubjectAltName,
				Value: sanContents,
			},
		},
	}

	csr := marshalAndParseCSR(t, &template)

	if len(csr.DNSNames) != 1 || csr.DNSNames[0] != "foo.example.com" {
		t.Errorf("Extension did not override template. Got %v\n", csr.DNSNames)
	}

	// If there is already an attribute with X.509 extensions then the
	// extra extensions should be added to it rather than creating a CSR
	// with two extension attributes.

	template.Attributes = []pkix.AttributeTypeAndValueSET{
		{
			Type: oidExtensionRequest,
			Value: [][]pkix.AttributeTypeAndValue{
				{
					{
						Type:  OIDExtensionAuthorityInfoAccess,
						Value: []byte("foo"),
					},
				},
			},
		},
	}

	csr = marshalAndParseCSR(t, &template)
	if l := len(csr.Attributes); l != 1 {
		t.Errorf("incorrect number of attributes: %d\n", l)
	}

	if !csr.Attributes[0].Type.Equal(oidExtensionRequest) ||
		len(csr.Attributes[0].Value) != 1 ||
		len(csr.Attributes[0].Value[0]) != 2 {
		t.Errorf("bad attributes: %#v\n", csr.Attributes)
	}

	sanContents2, err := marshalSANs([]string{"foo2.example.com"}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Extensions in Attributes should override those in ExtraExtensions.
	template.Attributes[0].Value[0] = append(template.Attributes[0].Value[0], pkix.AttributeTypeAndValue{
		Type:  OIDExtensionSubjectAltName,
		Value: sanContents2,
	})

	csr = marshalAndParseCSR(t, &template)

	if len(csr.DNSNames) != 1 || csr.DNSNames[0] != "foo2.example.com" {
		t.Errorf("Attributes did not override ExtraExtensions. Got %v\n", csr.DNSNames)
	}
}

func TestParseCertificateRequest(t *testing.T) {
	for _, csrBase64 := range csrBase64Array {
		csrBytes := fromBase64(csrBase64)
		csr, err := ParseCertificateRequest(csrBytes)
		if err != nil {
			t.Fatalf("failed to parse CSR: %s", err)
		}

		if len(csr.EmailAddresses) != 1 || csr.EmailAddresses[0] != "gopher@golang.org" {
			t.Errorf("incorrect email addresses found: %v", csr.EmailAddresses)
		}

		if len(csr.DNSNames) != 1 || csr.DNSNames[0] != "test.example.com" {
			t.Errorf("incorrect DNS names found: %v", csr.DNSNames)
		}

		if len(csr.Subject.Country) != 1 || csr.Subject.Country[0] != "AU" {
			t.Errorf("incorrect Subject name: %v", csr.Subject)
		}

		found := false
		for _, e := range csr.Extensions {
			if e.Id.Equal(OIDExtensionBasicConstraints) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("basic constraints extension not found in CSR")
		}
	}
}

func TestCriticalFlagInCSRRequestedExtensions(t *testing.T) {
	// This CSR contains an extension request where the extensions have a
	// critical flag in them. In the past we failed to handle this.
	const csrBase64 = "MIICrTCCAZUCAQIwMzEgMB4GA1UEAwwXU0NFUCBDQSBmb3IgRGV2ZWxlciBTcmwxDzANBgNVBAsMBjQzNTk3MTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALFMAJ7Zy9YyfgbNlbUWAW0LalNRMPs7aXmLANsCpjhnw3lLlfDPaLeWyKh1nK5I5ojaJOW6KIOSAcJkDUe3rrE0wR0RVt3UxArqs0R/ND3u5Q+bDQY2X1HAFUHzUzcdm5JRAIA355v90teMckaWAIlkRQjDE22Lzc6NAl64KOd1rqOUNj8+PfX6fSo20jm94Pp1+a6mfk3G/RUWVuSm7owO5DZI/Fsi2ijdmb4NUar6K/bDKYTrDFkzcqAyMfP3TitUtBp19Mp3B1yAlHjlbp/r5fSSXfOGHZdgIvp0WkLuK2u5eQrX5l7HMB/5epgUs3HQxKY6ljhh5wAjDwz//LsCAwEAAaA1MDMGCSqGSIb3DQEJDjEmMCQwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQEFBQADggEBAAMq3bxJSPQEgzLYR/yaVvgjCDrc3zUbIwdOis6Go06Q4RnjH5yRaSZAqZQTDsPurQcnz2I39VMGEiSkFJFavf4QHIZ7QFLkyXadMtALc87tm17Ej719SbHcBSSZayR9VYJUNXRLayI6HvyUrmqcMKh+iX3WY3ICr59/wlM0tYa8DYN4yzmOa2Onb29gy3YlaF5A2AKAMmk003cRT9gY26mjpv7d21czOSSeNyVIoZ04IR9ee71vWTMdv0hu/af5kSjQ+ZG5/Qgc0+mnECLz/1gtxt1srLYbtYQ/qAY8oX1DCSGFS61tN/vl+4cxGMD/VGcGzADRLRHSlVqy2Qgss6Q="

	csrBytes := fromBase64(csrBase64)
	csr, err := ParseCertificateRequest(csrBytes)
	if err != nil {
		t.Fatalf("failed to parse CSR: %s", err)
	}

	expected := []struct {
		Id    asn1.ObjectIdentifier
		Value []byte
	}{
		{OIDExtensionBasicConstraints, fromBase64("MAYBAf8CAQA=")},
		{OIDExtensionKeyUsage, fromBase64("AwIChA==")},
	}

	if n := len(csr.Extensions); n != len(expected) {
		t.Fatalf("expected to find %d extensions but found %d", len(expected), n)
	}

	for i, extension := range csr.Extensions {
		if !extension.Id.Equal(expected[i].Id) {
			t.Fatalf("extension #%d has unexpected type %v (expected %v)", i, extension.Id, expected[i].Id)
		}

		if !bytes.Equal(extension.Value, expected[i].Value) {
			t.Fatalf("extension #%d has unexpected contents %x (expected %x)", i, extension.Value, expected[i].Value)
		}
	}
}

// serialiseAndParse generates a self-signed certificate from template and
// returns a parsed version of it.
func serialiseAndParse(t *testing.T, template *Certificate) *Certificate {
	derBytes, err := CreateCertificate(rand.Reader, template, template, &testPrivateKey.PublicKey, testPrivateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %s", err)
		return nil
	}

	cert, err := ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %s", err)
		return nil
	}

	return cert
}

func TestMaxPathLen(t *testing.T) {
	template := &Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Σ Acme Co",
		},
		NotBefore: time.Unix(1000, 0),
		NotAfter:  time.Unix(100000, 0),

		BasicConstraintsValid: true,
		IsCA: true,
	}

	cert1 := serialiseAndParse(t, template)
	if m := cert1.MaxPathLen; m != -1 {
		t.Errorf("Omitting MaxPathLen didn't turn into -1, got %d", m)
	}
	if cert1.MaxPathLenZero {
		t.Errorf("Omitting MaxPathLen resulted in MaxPathLenZero")
	}

	template.MaxPathLen = 1
	cert2 := serialiseAndParse(t, template)
	if m := cert2.MaxPathLen; m != 1 {
		t.Errorf("Setting MaxPathLen didn't work. Got %d but set 1", m)
	}
	if cert2.MaxPathLenZero {
		t.Errorf("Setting MaxPathLen resulted in MaxPathLenZero")
	}

	template.MaxPathLen = 0
	template.MaxPathLenZero = true
	cert3 := serialiseAndParse(t, template)
	if m := cert3.MaxPathLen; m != 0 {
		t.Errorf("Setting MaxPathLenZero didn't work, got %d", m)
	}
	if !cert3.MaxPathLenZero {
		t.Errorf("Setting MaxPathLen to zero didn't result in MaxPathLenZero")
	}
}

func TestNoAuthorityKeyIdInSelfSignedCert(t *testing.T) {
	template := &Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Σ Acme Co",
		},
		NotBefore: time.Unix(1000, 0),
		NotAfter:  time.Unix(100000, 0),

		BasicConstraintsValid: true,
		IsCA:         true,
		SubjectKeyId: []byte{1, 2, 3, 4},
	}

	if cert := serialiseAndParse(t, template); len(cert.AuthorityKeyId) != 0 {
		t.Fatalf("self-signed certificate contained default authority key id")
	}

	template.AuthorityKeyId = []byte{1, 2, 3, 4}
	if cert := serialiseAndParse(t, template); len(cert.AuthorityKeyId) == 0 {
		t.Fatalf("self-signed certificate erased explicit authority key id")
	}
}

func TestASN1BitLength(t *testing.T) {
	tests := []struct {
		bytes  []byte
		bitLen int
	}{
		{nil, 0},
		{[]byte{0x00}, 0},
		{[]byte{0x00, 0x00}, 0},
		{[]byte{0xf0}, 4},
		{[]byte{0x88}, 5},
		{[]byte{0xff}, 8},
		{[]byte{0xff, 0x80}, 9},
		{[]byte{0xff, 0x81}, 16},
	}

	for i, test := range tests {
		if got := asn1BitLength(test.bytes); got != test.bitLen {
			t.Errorf("#%d: calculated bit-length of %d for %x, wanted %d", i, got, test.bytes, test.bitLen)
		}
	}
}

func TestVerifyEmptyCertificate(t *testing.T) {
	if _, err := new(Certificate).Verify(VerifyOptions{}); err != errNotParsed {
		t.Errorf("Verifying empty certificate resulted in unexpected error: %q (wanted %q)", err, errNotParsed)
	}
}

func TestInsecureAlgorithmErrorString(t *testing.T) {
	tests := []struct {
		sa   SignatureAlgorithm
		want string
	}{
		{MD2WithRSA, "x509: cannot verify signature: insecure algorithm MD2-RSA"},
		{-1, "x509: cannot verify signature: insecure algorithm -1"},
		{0, "x509: cannot verify signature: insecure algorithm 0"},
		{9999, "x509: cannot verify signature: insecure algorithm 9999"},
	}
	for i, tt := range tests {
		if got := fmt.Sprint(InsecureAlgorithmError(tt.sa)); got != tt.want {
			t.Errorf("%d. mismatch.\n got: %s\nwant: %s\n", i, got, tt.want)
		}
	}
}

// These CSR was generated with OpenSSL:
//  openssl req -out CSR.csr -new -sha256 -nodes -keyout privateKey.key -config openssl.cnf
//
// With openssl.cnf containing the following sections:
//   [ v3_req ]
//   basicConstraints = CA:FALSE
//   keyUsage = nonRepudiation, digitalSignature, keyEncipherment
//   subjectAltName = email:gopher@golang.org,DNS:test.example.com
//   [ req_attributes ]
//   challengePassword = ignored challenge
//   unstructuredName  = ignored unstructured name
var csrBase64Array = [...]string{
	// Just [ v3_req ]
	"MIIDHDCCAgQCAQAwfjELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEUMBIGA1UEAwwLQ29tbW9uIE5hbWUxITAfBgkqhkiG9w0BCQEWEnRlc3RAZW1haWwuYWRkcmVzczCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK1GY4YFx2ujlZEOJxQVYmsjUnLsd5nFVnNpLE4cV+77sgv9NPNlB8uhn3MXt5leD34rm/2BisCHOifPucYlSrszo2beuKhvwn4+2FxDmWtBEMu/QA16L5IvoOfYZm/gJTsPwKDqvaR0tTU67a9OtxwNTBMI56YKtmwd/o8d3hYv9cg+9ZGAZ/gKONcg/OWYx/XRh6bd0g8DMbCikpWgXKDsvvK1Nk+VtkDO1JxuBaj4Lz/p/MifTfnHoqHxWOWl4EaTs4Ychxsv34/rSj1KD1tJqorIv5Xv2aqv4sjxfbrYzX4kvS5SC1goIovLnhj5UjmQ3Qy8u65eow/LLWw+YFcCAwEAAaBZMFcGCSqGSIb3DQEJDjFKMEgwCQYDVR0TBAIwADALBgNVHQ8EBAMCBeAwLgYDVR0RBCcwJYERZ29waGVyQGdvbGFuZy5vcmeCEHRlc3QuZXhhbXBsZS5jb20wDQYJKoZIhvcNAQELBQADggEBAB6VPMRrchvNW61Tokyq3ZvO6/NoGIbuwUn54q6l5VZW0Ep5Nq8juhegSSnaJ0jrovmUgKDN9vEo2KxuAtwG6udS6Ami3zP+hRd4k9Q8djJPb78nrjzWiindLK5Fps9U5mMoi1ER8ViveyAOTfnZt/jsKUaRsscY2FzE9t9/o5moE6LTcHUS4Ap1eheR+J72WOnQYn3cifYaemsA9MJuLko+kQ6xseqttbh9zjqd9fiCSh/LNkzos9c+mg2yMADitaZinAh+HZi50ooEbjaT3erNq9O6RqwJlgD00g6MQdoz9bTAryCUhCQfkIaepmQ7BxS0pqWNW3MMwfDwx/Snz6g=",
	// Both [ v3_req ] and [ req_attributes ]
	"MIIDaTCCAlECAQAwfjELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEUMBIGA1UEAwwLQ29tbW9uIE5hbWUxITAfBgkqhkiG9w0BCQEWEnRlc3RAZW1haWwuYWRkcmVzczCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK1GY4YFx2ujlZEOJxQVYmsjUnLsd5nFVnNpLE4cV+77sgv9NPNlB8uhn3MXt5leD34rm/2BisCHOifPucYlSrszo2beuKhvwn4+2FxDmWtBEMu/QA16L5IvoOfYZm/gJTsPwKDqvaR0tTU67a9OtxwNTBMI56YKtmwd/o8d3hYv9cg+9ZGAZ/gKONcg/OWYx/XRh6bd0g8DMbCikpWgXKDsvvK1Nk+VtkDO1JxuBaj4Lz/p/MifTfnHoqHxWOWl4EaTs4Ychxsv34/rSj1KD1tJqorIv5Xv2aqv4sjxfbrYzX4kvS5SC1goIovLnhj5UjmQ3Qy8u65eow/LLWw+YFcCAwEAAaCBpTAgBgkqhkiG9w0BCQcxEwwRaWdub3JlZCBjaGFsbGVuZ2UwKAYJKoZIhvcNAQkCMRsMGWlnbm9yZWQgdW5zdHJ1Y3R1cmVkIG5hbWUwVwYJKoZIhvcNAQkOMUowSDAJBgNVHRMEAjAAMAsGA1UdDwQEAwIF4DAuBgNVHREEJzAlgRFnb3BoZXJAZ29sYW5nLm9yZ4IQdGVzdC5leGFtcGxlLmNvbTANBgkqhkiG9w0BAQsFAAOCAQEAgxe2N5O48EMsYE7o0rZBB0wi3Ov5/yYfnmmVI22Y3sP6VXbLDW0+UWIeSccOhzUCcZ/G4qcrfhhx6gTZTeA01nP7TdTJURvWAH5iFqj9sQ0qnLq6nEcVHij3sG6M5+BxAIVClQBk6lTCzgphc835Fjj6qSLuJ20XHdL5UfUbiJxx299CHgyBRL+hBUIPfz8p+ZgamyAuDLfnj54zzcRVyLlrmMLNPZNll1Q70RxoU6uWvLH8wB8vQe3Q/guSGubLyLRTUQVPh+dw1L4t8MKFWfX/48jwRM4gIRHFHPeAAE9D9YAoqdIvj/iFm/eQ++7DP8MDwOZWsXeB6jjwHuLmkQ==",
}

var md5cert = `
-----BEGIN CERTIFICATE-----
MIIB4TCCAUoCCQCfmw3vMgPS5TANBgkqhkiG9w0BAQQFADA1MQswCQYDVQQGEwJB
VTETMBEGA1UECBMKU29tZS1TdGF0ZTERMA8GA1UEChMITUQ1IEluYy4wHhcNMTUx
MjAzMTkyOTMyWhcNMjkwODEyMTkyOTMyWjA1MQswCQYDVQQGEwJBVTETMBEGA1UE
CBMKU29tZS1TdGF0ZTERMA8GA1UEChMITUQ1IEluYy4wgZ8wDQYJKoZIhvcNAQEB
BQADgY0AMIGJAoGBANrq2nhLQj5mlXbpVX3QUPhfEm/vdEqPkoWtR/jRZIWm4WGf
Wpq/LKHJx2Pqwn+t117syN8l4U5unyAi1BJSXjBwPZNd7dXjcuJ+bRLV7FZ/iuvs
cfYyQQFTxan4TaJMd0x1HoNDbNbjHa02IyjjYE/r3mb/PIg+J2t5AZEh80lPAgMB
AAEwDQYJKoZIhvcNAQEEBQADgYEAjGzp3K3ey/YfKHohf33yHHWd695HQxDAP+wY
cs9/TAyLR+gJzJP7d18EcDDLJWVi7bhfa4EAD86di05azOh9kWSn4b3o9QYRGCSw
GNnI3Zk0cwNKA49hZntKKiy22DhRk7JAHF01d6Bu3KkHkmENrtJ+zj/+159WAnUa
qViorq4=
-----END CERTIFICATE-----
`

func TestMD5(t *testing.T) {
	pemBlock, _ := pem.Decode([]byte(md5cert))
	cert, err := ParseCertificate(pemBlock.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %s", err)
	}
	if sa := cert.SignatureAlgorithm; sa != MD5WithRSA {
		t.Errorf("signature algorithm is %v, want %v", sa, MD5WithRSA)
	}
	if err = cert.CheckSignatureFrom(cert); err == nil {
		t.Fatalf("certificate verification succeeded incorrectly")
	}
	if _, ok := err.(InsecureAlgorithmError); !ok {
		t.Fatalf("certificate verification returned %v (%T), wanted InsecureAlgorithmError", err, err)
	}
}

// certMissingRSANULL contains an RSA public key where the AlgorithmIdentifer
// parameters are omitted rather than being an ASN.1 NULL.
const certMissingRSANULL = `
-----BEGIN CERTIFICATE-----
MIIB7TCCAVigAwIBAgIBADALBgkqhkiG9w0BAQUwJjEQMA4GA1UEChMHQWNtZSBD
bzESMBAGA1UEAxMJMTI3LjAuMC4xMB4XDTExMTIwODA3NTUxMloXDTEyMTIwNzA4
MDAxMlowJjEQMA4GA1UEChMHQWNtZSBDbzESMBAGA1UEAxMJMTI3LjAuMC4xMIGc
MAsGCSqGSIb3DQEBAQOBjAAwgYgCgYBO0Hsx44Jk2VnAwoekXh6LczPHY1PfZpIG
hPZk1Y/kNqcdK+izIDZFI7Xjla7t4PUgnI2V339aEu+H5Fto5OkOdOwEin/ekyfE
ARl6vfLcPRSr0FTKIQzQTW6HLlzF0rtNS0/Otiz3fojsfNcCkXSmHgwa2uNKWi7e
E5xMQIhZkwIDAQABozIwMDAOBgNVHQ8BAf8EBAMCAKAwDQYDVR0OBAYEBAECAwQw
DwYDVR0jBAgwBoAEAQIDBDALBgkqhkiG9w0BAQUDgYEANh+zegx1yW43RmEr1b3A
p0vMRpqBWHyFeSnIyMZn3TJWRSt1tukkqVCavh9a+hoV2cxVlXIWg7nCto/9iIw4
hB2rXZIxE0/9gzvGnfERYraL7KtnvshksBFQRlgXa5kc0x38BvEO5ZaoDPl4ILdE
GFGNEH5PlGffo05wc46QkYU=
-----END CERTIFICATE-----`

func TestRSAMissingNULLParameters(t *testing.T) {
	block, _ := pem.Decode([]byte(certMissingRSANULL))
	if _, err := ParseCertificate(block.Bytes); err == nil {
		t.Error("unexpected success when parsing certificate with missing RSA NULL parameter")
	} else if !strings.Contains(err.Error(), "missing NULL") {
		t.Errorf("unrecognised error when parsing certificate with missing RSA NULL parameter: %s", err)
	}
}

const certISOOID = `
-----BEGIN CERTIFICATE-----
MIIB5TCCAVKgAwIBAgIQtwyL3RPWV7dJQp34HwZG9DAJBgUrDgMCHQUAMBExDzAN
BgNVBAMTBm15dGVzdDAeFw0xNjA4MDkyMjExMDVaFw0zOTEyMzEyMzU5NTlaMBEx
DzANBgNVBAMTBm15dGVzdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEArzIH
GsyDB3ohIGkkvijF2PTRUX1bvOtY1eUUpjwHyu0twpAKSuaQv2Ha+/63+aHe8O86
BT+98wjXFX6RFSagtAujo80rIF2dSm33BGt18pDN8v6zp93dnAm0jRaSQrHJ75xw
5O+S1oEYR1LtUoFJy6qB104j6aINBAgOiLIKiMkCAwEAAaNGMEQwQgYDVR0BBDsw
OYAQVuYVQ/WDjdGSkZRlTtJDNKETMBExDzANBgNVBAMTBm15dGVzdIIQtwyL3RPW
V7dJQp34HwZG9DAJBgUrDgMCHQUAA4GBABngrSkH7vG5lY4sa4AZF59lAAXqBVJE
J4TBiKC62hCdZv18rBleP6ETfhbPg7pTs8p4ebQbpmtNxRS9Lw3MzQ8Ya5Ybwzj2
NwBSyCtCQl7mrEg4nJqJl4A2EUhnET/oVxU0oTV/SZ3ziGXcY1oG1s6vidV7TZTu
MCRtdSdaM7g3
-----END CERTIFICATE-----`

func TestISOOIDInCertificate(t *testing.T) {
	block, _ := pem.Decode([]byte(certISOOID))
	if cert, err := ParseCertificate(block.Bytes); err != nil {
		t.Errorf("certificate with ISO OID failed to parse: %s", err)
	} else if cert.SignatureAlgorithm == UnknownSignatureAlgorithm {
		t.Errorf("ISO OID not recognised in certificate")
	}
}

// certMultipleRDN contains a RelativeDistinguishedName with two elements (the
// common name and serial number). This particular certificate was the first
// such certificate in the “Pilot” Certificate Transparency log.
const certMultipleRDN = `
-----BEGIN CERTIFICATE-----
MIIFRzCCBC+gAwIBAgIEOl59NTANBgkqhkiG9w0BAQUFADA9MQswCQYDVQQGEwJz
aTEbMBkGA1UEChMSc3RhdGUtaW5zdGl0dXRpb25zMREwDwYDVQQLEwhzaWdvdi1j
YTAeFw0xMjExMTYxMDUyNTdaFw0xNzExMTYxMjQ5MDVaMIGLMQswCQYDVQQGEwJz
aTEbMBkGA1UEChMSc3RhdGUtaW5zdGl0dXRpb25zMRkwFwYDVQQLExB3ZWItY2Vy
dGlmaWNhdGVzMRAwDgYDVQQLEwdTZXJ2ZXJzMTIwFAYDVQQFEw0xMjM2NDg0MDEw
MDEwMBoGA1UEAxMTZXBvcnRhbC5tc3MuZWR1cy5zaTCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBAMrNkZH9MPuBTjMGNk3sJX8V+CkFx/4ru7RTlLS6dlYM
098dtSfJ3s2w0p/1NB9UmR8j0yS0Kg6yoZ3ShsSO4DWBtcQD8820a6BYwqxxQTNf
HSRZOc+N/4TQrvmK6t4k9Aw+YEYTMrWOU4UTeyhDeCcUsBdh7HjfWsVaqNky+2sv
oic3zP5gF+2QfPkvOoHT3FLR8olNhViIE6Kk3eFIEs4dkq/ZzlYdLb8pHQoj/sGI
zFmA5AFvm1HURqOmJriFjBwaCtn8AVEYOtQrnUCzJYu1ex8azyS2ZgYMX0u8A5Z/
y2aMS/B2W+H79WcgLpK28vPwe7vam0oFrVytAd+u65ECAwEAAaOCAf4wggH6MA4G
A1UdDwEB/wQEAwIFoDBABgNVHSAEOTA3MDUGCisGAQQBr1kBAwMwJzAlBggrBgEF
BQcCARYZaHR0cDovL3d3dy5jYS5nb3Yuc2kvY3BzLzAfBgNVHREEGDAWgRRwb2Rw
b3JhLm1pemtzQGdvdi5zaTCB8QYDVR0fBIHpMIHmMFWgU6BRpE8wTTELMAkGA1UE
BhMCc2kxGzAZBgNVBAoTEnN0YXRlLWluc3RpdHV0aW9uczERMA8GA1UECxMIc2ln
b3YtY2ExDjAMBgNVBAMTBUNSTDM5MIGMoIGJoIGGhldsZGFwOi8veDUwMC5nb3Yu
c2kvb3U9c2lnb3YtY2Esbz1zdGF0ZS1pbnN0aXR1dGlvbnMsYz1zaT9jZXJ0aWZp
Y2F0ZVJldm9jYXRpb25MaXN0P2Jhc2WGK2h0dHA6Ly93d3cuc2lnb3YtY2EuZ292
LnNpL2NybC9zaWdvdi1jYS5jcmwwKwYDVR0QBCQwIoAPMjAxMjExMTYxMDUyNTda
gQ8yMDE3MTExNjEyNDkwNVowHwYDVR0jBBgwFoAUHvjUU2uzgwbpBAZXAvmlv8ZY
PHIwHQYDVR0OBBYEFGI1Duuu+wTGDZka/xHNbwcbM69ZMAkGA1UdEwQCMAAwGQYJ
KoZIhvZ9B0EABAwwChsEVjcuMQMCA6gwDQYJKoZIhvcNAQEFBQADggEBAHny0K1y
BQznrzDu3DDpBcGYguKU0dvU9rqsV1ua4nxkriSMWjgsX6XJFDdDW60I3P4VWab5
ag5fZzbGqi8kva/CzGgZh+CES0aWCPy+4Gb8lwOTt+854/laaJvd6kgKTER7z7U9
9C86Ch2y4sXNwwwPJ1A9dmrZJZOcJjS/WYZgwaafY2Hdxub5jqPE5nehwYUPVu9R
uH6/skk4OEKcfOtN0hCnISOVuKYyS4ANARWRG5VGHIH06z3lGUVARFRJ61gtAprd
La+fgSS+LVZ+kU2TkeoWAKvGq8MAgDq4D4Xqwekg7WKFeuyusi/NI5rm40XgjBMF
DF72IUofoVt7wo0=
-----END CERTIFICATE-----`

func TestMultipleRDN(t *testing.T) {
	block, _ := pem.Decode([]byte(certMultipleRDN))
	cert, err := ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("certificate with two elements in an RDN failed to parse: %v", err)
	}

	if want := "eportal.mss.edus.si"; cert.Subject.CommonName != want {
		t.Errorf("got common name of %q, but want %q", cert.Subject.CommonName, want)
	}

	if want := "1236484010010"; cert.Subject.SerialNumber != want {
		t.Errorf("got serial number of %q, but want %q", cert.Subject.SerialNumber, want)
	}
}

func TestSystemCertPool(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("not implemented on Windows; Issue 16736, 18609")
	}
	_, err := SystemCertPool()
	if err != nil {
		t.Fatal(err)
	}
}

const emptyNameConstraintsPEM = `
-----BEGIN CERTIFICATE-----
MIIC1jCCAb6gAwIBAgICEjQwDQYJKoZIhvcNAQELBQAwKDEmMCQGA1UEAxMdRW1w
dHkgbmFtZSBjb25zdHJhaW50cyBpc3N1ZXIwHhcNMTMwMjAxMDAwMDAwWhcNMjAw
NTMwMTA0ODM4WjAhMR8wHQYDVQQDExZFbXB0eSBuYW1lIGNvbnN0cmFpbnRzMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwriElUIt3LCqmJObs+yDoWPD
F5IqgWk6moIobYjPfextZiYU6I3EfvAwoNxPDkN2WowcocUZMJbEeEq5ebBksFnx
f12gBxlIViIYwZAzu7aFvhDMyPKQI3C8CG0ZSC9ABZ1E3umdA3CEueNOmP/TChNq
Cl23+BG1Qb/PJkpAO+GfpWSVhTcV53Mf/cKvFHcjGNrxzdSoq9fyW7a6gfcGEQY0
LVkmwFWUfJ0wT8kaeLr0E0tozkIfo01KNWNzv6NcYP80QOBRDlApWu9ODmEVJHPD
blx4jzTQ3JLa+4DvBNOjVUOp+mgRmjiW0rLdrxwOxIqIOwNjweMCp/hgxX/hTQID
AQABoxEwDzANBgNVHR4EBjAEoAChADANBgkqhkiG9w0BAQsFAAOCAQEAWG+/zUMH
QhP8uNCtgSHyim/vh7wminwAvWgMKxlkLBFns6nZeQqsOV1lABY7U0Zuoqa1Z5nb
6L+iJa4ElREJOi/erLc9uLwBdDCAR0hUTKD7a6i4ooS39DTle87cUnj0MW1CUa6H
v5SsvpYW+1XleYJk/axQOOTcy4Es53dvnZsjXH0EA/QHnn7UV+JmlE3rtVxcYp6M
LYPmRhTioROA/drghicRkiu9hxdPyxkYS16M5g3Zj30jdm+k/6C6PeNtN9YmOOga
nCOSyFYfGhqOANYzpmuV+oIedAsPpIbfIzN8njYUs1zio+1IoI4o8ddM9sCbtPU8
o+WoY6IsCKXV/g==
-----END CERTIFICATE-----`

func TestEmptyNameConstraints(t *testing.T) {
	block, _ := pem.Decode([]byte(emptyNameConstraintsPEM))
	_, err := ParseCertificate(block.Bytes)
	if err == nil {
		t.Fatal("unexpected success")
	}

	const expected = "empty name constraints"
	if str := err.Error(); !strings.Contains(str, expected) {
		t.Errorf("expected %q in error but got %q", expected, str)
	}
}

func TestPKIXNameString(t *testing.T) {
	pem, err := hex.DecodeString(certBytes)
	if err != nil {
		t.Fatal(err)
	}
	certs, err := ParseCertificates(pem)
	if IsFatal(err) {
		t.Fatal(err)
	}

	tests := []struct {
		dn   pkix.Name
		want string
	}{
		{pkix.Name{
			CommonName:         "Steve Kille",
			Organization:       []string{"Isode Limited"},
			OrganizationalUnit: []string{"RFCs"},
			Locality:           []string{"Richmond"},
			Province:           []string{"Surrey"},
			StreetAddress:      []string{"The Square"},
			PostalCode:         []string{"TW9 1DT"},
			SerialNumber:       "RFC 2253",
			Country:            []string{"GB"},
		}, "SERIALNUMBER=RFC 2253,CN=Steve Kille,OU=RFCs,O=Isode Limited,POSTALCODE=TW9 1DT,STREET=The Square,L=Richmond,ST=Surrey,C=GB"},
		{certs[0].Subject,
			"CN=mail.google.com,O=Google Inc,L=Mountain View,ST=California,C=US"},
		{pkix.Name{
			Organization: []string{"#Google, Inc. \n-> 'Alphabet\" "},
			Country:      []string{"US"},
		}, "O=\\#Google\\, Inc. \n-\\> 'Alphabet\\\"\\ ,C=US"},
		{pkix.Name{
			CommonName:   "foo.com",
			Organization: []string{"Gopher Industries"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier([]int{2, 5, 4, 3}), Value: "bar.com"}},
		}, "CN=bar.com,O=Gopher Industries"},
		{pkix.Name{
			Locality: []string{"Gophertown"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier([]int{1, 2, 3, 4, 5}), Value: "golang.org"}},
		}, "1.2.3.4.5=#130a676f6c616e672e6f7267,L=Gophertown"},
	}

	for i, test := range tests {
		if got := test.dn.String(); got != test.want {
			t.Errorf("#%d: String() = \n%s\n, want \n%s", i, got, test.want)
		}
	}
}

func TestRDNSequenceString(t *testing.T) {
	// Test some extra cases that get lost in pkix.Name conversions such as
	// multi-valued attributes.

	var (
		oidCountry            = []int{2, 5, 4, 6}
		oidOrganization       = []int{2, 5, 4, 10}
		oidOrganizationalUnit = []int{2, 5, 4, 11}
		oidCommonName         = []int{2, 5, 4, 3}
	)

	tests := []struct {
		seq  pkix.RDNSequence
		want string
	}{
		{
			seq: pkix.RDNSequence{
				pkix.RelativeDistinguishedNameSET{
					pkix.AttributeTypeAndValue{Type: oidCountry, Value: "US"},
				},
				pkix.RelativeDistinguishedNameSET{
					pkix.AttributeTypeAndValue{Type: oidOrganization, Value: "Widget Inc."},
				},
				pkix.RelativeDistinguishedNameSET{
					pkix.AttributeTypeAndValue{Type: oidOrganizationalUnit, Value: "Sales"},
					pkix.AttributeTypeAndValue{Type: oidCommonName, Value: "J. Smith"},
				},
			},
			want: "OU=Sales+CN=J. Smith,O=Widget Inc.,C=US",
		},
	}

	for i, test := range tests {
		if got := test.seq.String(); got != test.want {
			t.Errorf("#%d: String() = \n%s\n, want \n%s", i, got, test.want)
		}
	}
}

const criticalNameConstraintWithUnknownTypePEM = `
-----BEGIN CERTIFICATE-----
MIIC/TCCAeWgAwIBAgICEjQwDQYJKoZIhvcNAQELBQAwKDEmMCQGA1UEAxMdRW1w
dHkgbmFtZSBjb25zdHJhaW50cyBpc3N1ZXIwHhcNMTMwMjAxMDAwMDAwWhcNMjAw
NTMwMTA0ODM4WjAhMR8wHQYDVQQDExZFbXB0eSBuYW1lIGNvbnN0cmFpbnRzMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwriElUIt3LCqmJObs+yDoWPD
F5IqgWk6moIobYjPfextZiYU6I3EfvAwoNxPDkN2WowcocUZMJbEeEq5ebBksFnx
f12gBxlIViIYwZAzu7aFvhDMyPKQI3C8CG0ZSC9ABZ1E3umdA3CEueNOmP/TChNq
Cl23+BG1Qb/PJkpAO+GfpWSVhTcV53Mf/cKvFHcjGNrxzdSoq9fyW7a6gfcGEQY0
LVkmwFWUfJ0wT8kaeLr0E0tozkIfo01KNWNzv6NcYP80QOBRDlApWu9ODmEVJHPD
blx4jzTQ3JLa+4DvBNOjVUOp+mgRmjiW0rLdrxwOxIqIOwNjweMCp/hgxX/hTQID
AQABozgwNjA0BgNVHR4BAf8EKjAooCQwIokgIACrzQAAAAAAAAAAAAAAAP////8A
AAAAAAAAAAAAAAChADANBgkqhkiG9w0BAQsFAAOCAQEAWG+/zUMHQhP8uNCtgSHy
im/vh7wminwAvWgMKxlkLBFns6nZeQqsOV1lABY7U0Zuoqa1Z5nb6L+iJa4ElREJ
Oi/erLc9uLwBdDCAR0hUTKD7a6i4ooS39DTle87cUnj0MW1CUa6Hv5SsvpYW+1Xl
eYJk/axQOOTcy4Es53dvnZsjXH0EA/QHnn7UV+JmlE3rtVxcYp6MLYPmRhTioROA
/drghicRkiu9hxdPyxkYS16M5g3Zj30jdm+k/6C6PeNtN9YmOOganCOSyFYfGhqO
ANYzpmuV+oIedAsPpIbfIzN8njYUs1zio+1IoI4o8ddM9sCbtPU8o+WoY6IsCKXV
/g==
-----END CERTIFICATE-----`

func TestCriticalNameConstraintWithUnknownType(t *testing.T) {
	block, _ := pem.Decode([]byte(criticalNameConstraintWithUnknownTypePEM))
	cert, err := ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("unexpected parsing failure: %s", err)
	}

	if l := len(cert.UnhandledCriticalExtensions); l != 1 {
		t.Fatalf("expected one unhandled critical extension, but found %d", l)
	}
}

const badIPMaskPEM = `
-----BEGIN CERTIFICATE-----
MIICzzCCAbegAwIBAgICEjQwDQYJKoZIhvcNAQELBQAwHTEbMBkGA1UEAxMSQmFk
IElQIG1hc2sgaXNzdWVyMB4XDTEzMDIwMTAwMDAwMFoXDTIwMDUzMDEwNDgzOFow
FjEUMBIGA1UEAxMLQmFkIElQIG1hc2swggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDCuISVQi3csKqYk5uz7IOhY8MXkiqBaTqagihtiM997G1mJhTojcR+
8DCg3E8OQ3ZajByhxRkwlsR4Srl5sGSwWfF/XaAHGUhWIhjBkDO7toW+EMzI8pAj
cLwIbRlIL0AFnUTe6Z0DcIS5406Y/9MKE2oKXbf4EbVBv88mSkA74Z+lZJWFNxXn
cx/9wq8UdyMY2vHN1Kir1/JbtrqB9wYRBjQtWSbAVZR8nTBPyRp4uvQTS2jOQh+j
TUo1Y3O/o1xg/zRA4FEOUCla704OYRUkc8NuXHiPNNDcktr7gO8E06NVQ6n6aBGa
OJbSst2vHA7Eiog7A2PB4wKn+GDFf+FNAgMBAAGjIDAeMBwGA1UdHgEB/wQSMBCg
DDAKhwgBAgME//8BAKEAMA0GCSqGSIb3DQEBCwUAA4IBAQBYb7/NQwdCE/y40K2B
IfKKb++HvCaKfAC9aAwrGWQsEWezqdl5Cqw5XWUAFjtTRm6iprVnmdvov6IlrgSV
EQk6L96stz24vAF0MIBHSFRMoPtrqLiihLf0NOV7ztxSePQxbUJRroe/lKy+lhb7
VeV5gmT9rFA45NzLgSznd2+dmyNcfQQD9AeeftRX4maUTeu1XFxinowtg+ZGFOKh
E4D92uCGJxGSK72HF0/LGRhLXozmDdmPfSN2b6T/oLo942031iY46BqcI5LIVh8a
Go4A1jOma5X6gh50Cw+kht8jM3yeNhSzXOKj7Uigjijx10z2wJu09Tyj5ahjoiwI
pdX+
-----END CERTIFICATE-----`

func TestBadIPMask(t *testing.T) {
	block, _ := pem.Decode([]byte(badIPMaskPEM))
	_, err := ParseCertificate(block.Bytes)
	if err == nil {
		t.Fatalf("unexpected success")
	}

	const expected = "contained invalid mask"
	if !strings.Contains(err.Error(), expected) {
		t.Fatalf("expected %q in error but got: %s", expected, err)
	}
}

const additionalGeneralSubtreePEM = `
-----BEGIN CERTIFICATE-----
MIIG4TCCBMmgAwIBAgIRALss+4rLw2Ia7tFFhxE8g5cwDQYJKoZIhvcNAQELBQAw
bjELMAkGA1UEBhMCTkwxIDAeBgNVBAoMF01pbmlzdGVyaWUgdmFuIERlZmVuc2ll
MT0wOwYDVQQDDDRNaW5pc3RlcmllIHZhbiBEZWZlbnNpZSBDZXJ0aWZpY2F0aWUg
QXV0b3JpdGVpdCAtIEcyMB4XDTEzMDMwNjEyMDM0OVoXDTEzMTEzMDEyMDM1MFow
bDELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUNlcnRpUGF0aCBMTEMxIjAgBgNVBAsT
GUNlcnRpZmljYXRpb24gQXV0aG9yaXRpZXMxITAfBgNVBAMTGENlcnRpUGF0aCBC
cmlkZ2UgQ0EgLSBHMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANLW
4kXiRqvwBhJfN9uz12FA+P2D34MPxOt7TGXljm2plJ2CLzvaH8/ymsMdSWdJBS1M
8FmwvNL1w3A6ZuzksJjPikAu8kY3dcp3mrkk9eCPORDAwGtfsXwZysLiuEaDWpbD
dHOaHnI6qWU0N6OI+hNX58EjDpIGC1WQdho1tHOTPc5Hf5/hOpM/29v/wr7kySjs
Z+7nsvkm5rNhuJNzPsLsgzVaJ5/BVyOplZy24FKM8Y43MjR4osZm+a2e0zniqw6/
rvcjcGYabYaznZfQG1GXoyf2Vea+CCgpgUhlVafgkwEs8izl8rIpvBzXiFAgFQuG
Ituoy92PJbDs430fA/cCAwEAAaOCAnowggJ2MEUGCCsGAQUFBwEBBDkwNzA1Bggr
BgEFBQcwAoYpaHR0cDovL2NlcnRzLmNhLm1pbmRlZi5ubC9taW5kZWYtY2EtMi5w
N2MwHwYDVR0jBBgwFoAUzln9WSPz2M64Rl2HYf2/KD8StmQwDwYDVR0TAQH/BAUw
AwEB/zCB6QYDVR0gBIHhMIHeMEgGCmCEEAGHawECBQEwOjA4BggrBgEFBQcCARYs
aHR0cDovL2Nwcy5kcC5jYS5taW5kZWYubmwvbWluZGVmLWNhLWRwLWNwcy8wSAYK
YIQQAYdrAQIFAjA6MDgGCCsGAQUFBwIBFixodHRwOi8vY3BzLmRwLmNhLm1pbmRl
Zi5ubC9taW5kZWYtY2EtZHAtY3BzLzBIBgpghBABh2sBAgUDMDowOAYIKwYBBQUH
AgEWLGh0dHA6Ly9jcHMuZHAuY2EubWluZGVmLm5sL21pbmRlZi1jYS1kcC1jcHMv
MDkGA1UdHwQyMDAwLqAsoCqGKGh0dHA6Ly9jcmxzLmNhLm1pbmRlZi5ubC9taW5k
ZWYtY2EtMi5jcmwwDgYDVR0PAQH/BAQDAgEGMEYGA1UdHgEB/wQ8MDqhODA2pDEw
LzELMAkGA1UEBhMCTkwxIDAeBgNVBAoTF01pbmlzdGVyaWUgdmFuIERlZmVuc2ll
gQFjMF0GA1UdIQRWMFQwGgYKYIQQAYdrAQIFAQYMKwYBBAGBu1MBAQECMBoGCmCE
EAGHawECBQIGDCsGAQQBgbtTAQEBAjAaBgpghBABh2sBAgUDBgwrBgEEAYG7UwEB
AQIwHQYDVR0OBBYEFNDCjBM3M3ZKkag84ei3/aKc0d0UMA0GCSqGSIb3DQEBCwUA
A4ICAQAQXFn9jF90/DNFf15JhoGtta/0dNInb14PMu3PAjcdrXYCDPpQZOArTUng
5YT1WuzfmjnXiTsziT3my0r9Mxvz/btKK/lnVOMW4c2q/8sIsIPnnW5ZaRGrsANB
dNDZkzMYmeG2Pfgvd0AQSOrpE/TVgWfu/+MMRWwX9y6VbooBR7BLv7zMuVH0WqLn
6OMFth7fqsThlfMSzkE/RDSaU6n3wXAWT1SIqBITtccRjSUQUFm/q3xrb2cwcZA6
8vdS4hzNd+ttS905ay31Ks4/1Wrm1bH5RhEfRSH0VSXnc0b+z+RyBbmiwtVZqzxE
u3UQg/rAmtLDclLFEzjp8YDTIRYSLwstDbEXO/0ArdGrQm79HQ8i/3ZbP2357myW
i15qd6gMJIgGHS4b8Hc7R1K8LQ9Gm1aLKBEWVNGZlPK/cpXThpVmoEyslN2DHCrc
fbMbjNZpXlTMa+/b9z7Fa4X8dY8u/ELzZuJXJv5Rmqtg29eopFFYDCl0Nkh1XAjo
QejEoHHUvYV8TThHZr6Z6Ib8CECgTehU4QvepkgDXNoNrKRZBG0JhLjkwxh2whZq
nvWBfALC2VuNOM6C0rDY+HmhMlVt0XeqnybD9MuQALMit7Z00Cw2CIjNsBI9xBqD
xKK9CjUb7gzRUWSpB9jGHsvpEMHOzIFhufvH2Bz1XJw+Cl7khw==
-----END CERTIFICATE-----`

func TestAdditionFieldsInGeneralSubtree(t *testing.T) {
	// Very rarely, certificates can include additional fields in the
	// GeneralSubtree structure. This tests that such certificates can be
	// parsed.
	block, _ := pem.Decode([]byte(additionalGeneralSubtreePEM))
	if _, err := ParseCertificate(block.Bytes); IsFatal(err) {
		t.Fatalf("failed to parse certificate: %s", err)
	}
}

func TestEmptySubject(t *testing.T) {
	template := Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"example.com"},
	}

	derBytes, err := CreateCertificate(rand.Reader, &template, &template, &testPrivateKey.PublicKey, testPrivateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %s", err)
	}

	cert, err := ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %s", err)
	}

	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDExtensionSubjectAltName) {
			if !ext.Critical {
				t.Fatal("SAN extension is not critical")
			}
			return
		}
	}

	t.Fatal("SAN extension is missing")
}

// multipleURLsInCRLDPPEM contains two URLs in a single CRL DistributionPoint
// structure. It is taken from https://crt.sh/?id=12721534.
const multipleURLsInCRLDPPEM = `
-----BEGIN CERTIFICATE-----
MIIF4TCCBMmgAwIBAgIQc+6uFePfrahUGpXs8lhiTzANBgkqhkiG9w0BAQsFADCB
8zELMAkGA1UEBhMCRVMxOzA5BgNVBAoTMkFnZW5jaWEgQ2F0YWxhbmEgZGUgQ2Vy
dGlmaWNhY2lvIChOSUYgUS0wODAxMTc2LUkpMSgwJgYDVQQLEx9TZXJ2ZWlzIFB1
YmxpY3MgZGUgQ2VydGlmaWNhY2lvMTUwMwYDVQQLEyxWZWdldSBodHRwczovL3d3
dy5jYXRjZXJ0Lm5ldC92ZXJhcnJlbCAoYykwMzE1MDMGA1UECxMsSmVyYXJxdWlh
IEVudGl0YXRzIGRlIENlcnRpZmljYWNpbyBDYXRhbGFuZXMxDzANBgNVBAMTBkVD
LUFDQzAeFw0xNDA5MTgwODIxMDBaFw0zMDA5MTgwODIxMDBaMIGGMQswCQYDVQQG
EwJFUzEzMDEGA1UECgwqQ09OU09SQ0kgQURNSU5JU1RSQUNJTyBPQkVSVEEgREUg
Q0FUQUxVTllBMSowKAYDVQQLDCFTZXJ2ZWlzIFDDumJsaWNzIGRlIENlcnRpZmlj
YWNpw7MxFjAUBgNVBAMMDUVDLUNpdXRhZGFuaWEwggEiMA0GCSqGSIb3DQEBAQUA
A4IBDwAwggEKAoIBAQDFkHPRZPZlXTWZ5psJhbS/Gx+bxcTpGrlVQHHtIkgGz77y
TA7UZUFb2EQMncfbOhR0OkvQQn1aMvhObFJSR6nI+caf2D+h/m/InMl1MyH3S0Ak
YGZZsthnyC6KxqK2A/NApncrOreh70ULkQs45aOKsi1kR1W0zE+iFN+/P19P7AkL
Rl3bXBCVd8w+DLhcwRrkf1FCDw6cEqaFm3cGgf5cbBDMaVYAweWTxwBZAq2RbQAW
jE7mledcYghcZa4U6bUmCBPuLOnO8KMFAvH+aRzaf3ws5/ZoOVmryyLLJVZ54peZ
OwnP9EL4OuWzmXCjBifXR2IAblxs5JYj57tls45nAgMBAAGjggHaMIIB1jASBgNV
HRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUC2hZPofI
oxUa4ECCIl+fHbLFNxUwHwYDVR0jBBgwFoAUoMOLRKo3pUW/l4Ba0fF4opvpXY0w
gdYGA1UdIASBzjCByzCByAYEVR0gADCBvzAxBggrBgEFBQcCARYlaHR0cHM6Ly93
d3cuYW9jLmNhdC9DQVRDZXJ0L1JlZ3VsYWNpbzCBiQYIKwYBBQUHAgIwfQx7QXF1
ZXN0IGNlcnRpZmljYXQgw6lzIGVtw6hzIMO6bmljYSBpIGV4Y2x1c2l2YW1lbnQg
YSBFbnRpdGF0cyBkZSBDZXJ0aWZpY2FjacOzLiBWZWdldSBodHRwczovL3d3dy5h
b2MuY2F0L0NBVENlcnQvUmVndWxhY2lvMDMGCCsGAQUFBwEBBCcwJTAjBggrBgEF
BQcwAYYXaHR0cDovL29jc3AuY2F0Y2VydC5jYXQwYgYDVR0fBFswWTBXoFWgU4Yn
aHR0cDovL2Vwc2NkLmNhdGNlcnQubmV0L2NybC9lYy1hY2MuY3JshihodHRwOi8v
ZXBzY2QyLmNhdGNlcnQubmV0L2NybC9lYy1hY2MuY3JsMA0GCSqGSIb3DQEBCwUA
A4IBAQChqFTjlAH5PyIhLjLgEs68CyNNC1+vDuZXRhy22TI83JcvGmQrZosPvVIL
PsUXx+C06Pfqmh48Q9S89X9K8w1SdJxP/rZeGEoRiKpwvQzM4ArD9QxyC8jirxex
3Umg9Ai/sXQ+1lBf6xw4HfUUr1WIp7pNHj0ZWLo106urqktcdeAFWme+/klis5fu
labCSVPuT/QpwakPrtqOhRms8vgpKiXa/eLtL9ZiA28X/Mker0zlAeTA7Z7uAnp6
oPJTlZu1Gg1ZDJueTWWsLlO+P+Wzm3MRRIbcgdRzm4mdO7ubu26SzX/aQXDhuih+
eVxXDTCfs7GUlxnjOp5j559X/N0A
-----END CERTIFICATE-----
`

func TestMultipleURLsInCRLDP(t *testing.T) {
	block, _ := pem.Decode([]byte(multipleURLsInCRLDPPEM))
	cert, err := ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %s", err)
	}

	want := []string{
		"http://epscd.catcert.net/crl/ec-acc.crl",
		"http://epscd2.catcert.net/crl/ec-acc.crl",
	}
	if got := cert.CRLDistributionPoints; !reflect.DeepEqual(got, want) {
		t.Errorf("CRL distribution points = %#v, want #%v", got, want)
	}
}

func TestParseCertificateFail(t *testing.T) {
	var tests = []struct {
		desc    string
		in      string
		wantErr string
	}{
		{desc: "SubjectInfoEmpty", in: "testdata/invalid/xf-ext-subject-info-empty.pem", wantErr: "empty SubjectInfoAccess"},
		{desc: "RSAParamsNonNULL", in: "testdata/invalid/xf-pubkey-rsa-param-nonnull.pem", wantErr: "RSA key missing NULL parameters"},
		{desc: "EmptyEKU", in: "testdata/invalid/xf-ext-extended-key-usage-empty.pem", wantErr: "empty ExtendedKeyUsage"},
	}
	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			data, err := ioutil.ReadFile(test.in)
			if err != nil {
				t.Fatalf("failed to read test data: %v", err)
			}
			block, _ := pem.Decode(data)
			got, err := ParseCertificate(block.Bytes)
			if err == nil {
				t.Fatalf("ParseCertificate()=%+v,nil; want nil, err containing %q", got, test.wantErr)
			}
			if !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("ParseCertificate()=_,%v; want nil, err containing %q", err, test.wantErr)
			}
		})
	}
}
