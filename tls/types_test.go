// Copyright 2016 Google Inc. All Rights Reserved.
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

package tls

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestHashAlgorithmString(t *testing.T) {
	var tests = []struct {
		algo HashAlgorithm
		want string
	}{
		{None, "None"},
		{MD5, "MD5"},
		{SHA1, "SHA1"},
		{SHA224, "SHA224"},
		{SHA256, "SHA256"},
		{SHA384, "SHA384"},
		{SHA512, "SHA512"},
		{99, "UNKNOWN(99)"},
	}
	for _, test := range tests {
		if got := test.algo.String(); got != test.want {
			t.Errorf("%v.String()=%q; want %q", test.algo, got, test.want)
		}
	}
}

func TestSignatureAlgorithmString(t *testing.T) {
	var tests = []struct {
		algo SignatureAlgorithm
		want string
	}{
		{Anonymous, "Anonymous"},
		{RSA, "RSA"},
		{DSA, "DSA"},
		{ECDSA, "ECDSA"},
		{99, "UNKNOWN(99)"},
	}
	for _, test := range tests {
		if got := test.algo.String(); got != test.want {
			t.Errorf("%v.String()=%q; want %q", test.algo, got, test.want)
		}
	}
}

func TestDigitallySignedString(t *testing.T) {
	var tests = []struct {
		ds   DigitallySigned
		want string
	}{
		{
			ds:   DigitallySigned{Algorithm: SignatureAndHashAlgorithm{Hash: SHA1, Signature: RSA}, Signature: []byte{0x01, 0x02}},
			want: "Signature: HashAlgo=SHA1 SignAlgo=RSA Value=0102",
		},
		{
			ds:   DigitallySigned{Algorithm: SignatureAndHashAlgorithm{Hash: 99, Signature: 99}, Signature: []byte{0x03, 0x04}},
			want: "Signature: HashAlgo=UNKNOWN(99) SignAlgo=UNKNOWN(99) Value=0304",
		},
	}
	for _, test := range tests {
		if got := test.ds.String(); got != test.want {
			t.Errorf("%v.String()=%q; want %q", test.ds, got, test.want)
		}
	}
}

const (
	ecdsaPublicKey = `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEvuynpVdR+5xSNaVBb//1fqO6Nb/nC+WvRQ4bALzy4G+QbByvO1Qpm2eUzTdDUnsLN5hp3pIXYAmtjvjY1fFZEg==
-----END PUBLIC KEY-----`

	rsaPublicKey = `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsMB4reLZhs+2ReYX01nZpqLBQ9uhcZvBmzH54RsZDTb5khw+luSXKbLKXxdbQfrsxURbeVdugDNnV897VI43znuiKJ19Y/XS3N5Z7Q97/GOxOxGFObP0DovCAPblxAMaQBb+U9jkVt/4bHcNIOTZl/lXgX+yp58lH5uPfDwav/hVNg7QkAW3BxQZ5wiLTTZUILoTMjax4R24pULlg/Wt/rT4bDj8rxUgYR60MuO93jdBtNGwmzdCYyk4cEmrPEgCueRC6jFafUzlLjvuX89ES9n98LxX+gBANA7RpVPkJd0kfWFHO1JRUEJr++WjU3x4la2Xs4tUNX4QBSJP4XEOXwIDAQAB
-----END PUBLIC KEY-----`

	dsaPublicKey = `
-----BEGIN PUBLIC KEY-----
MIIDRjCCAjkGByqGSM44BAEwggIsAoIBAQDgLI6pXvqpcOY33lzeZrjUBHxphiz0I9VKF9vGpWymNfBptQ75bpQFe16jBjaOGwDImASHTp53XskQJLOXC4bZxoRUHsm8bHQVZHQhYgxn8ZDQX/40zOR1d73y1TXSiULo6rDKVlM+fFcm33tGv+ZOdfaIhW17c5jvDAy6UWqQakasvL+kfiejIDGHjLVFWwX0vLCG+pAomgO6snQHGcPhDO9uxEYPd9on7YTgBrpa2IcXk5jFeY8xOxMnMwoBojRvH97+ivdBR1yW8f+4FAGg5o1eFV5ZqoUAF8GO3BBEwluMGNeT7gMgl4PO8N8xBxJulHd3tLW5qkW0cBPwkbzzAiEAvdYeMPamsFAyd7s07dt78wxXyHGrwVl2AcQBo0QTATkCggEASH9Rp+EjNkL7uCqGJ78P4tjJM+2+xaEhZpJ/kTzq6DtdFhu5Rov6lN5NnZKPSUNYr9Vkmu88ru0iND1N37z0rJpImksXKxCv0AwBkwtqCwf9jjkTrZiGRzP8xf789wK+uG7Uud20ml9QzXKr9Af9WrRx3DtCq44PBaIlhPvpZS9znCZsuUZqYZFW3/oD4EhwPgVLSWeulh1t33ku3mYQwVS8ZTdJGPyFRoD1dcQ4EchR4ce0u0nTXlqErWhfnmb9msF6dFCV0Mx5yrqxkEHbJ/vZgB4zAdOke7XiJsWqIok/7IJpJuVOvkY9NHgBdlq3xU180+pEo2NrGm4pbrGm1wOCAQUAAoIBAAGbucHEfgtcu++OQQjYqneukv4zqcP/PCJTP+GuXen6SH25V2ZlHC88lG6qdZVBPWZidAb9BSoUQpW7BzauKRqH7rKOsIeqvEPCiWBKA781Zi5HAWGhC4INJJx54Q66F54DkGlTRVFkXlGpAIudhfAIG//MyO9TIsLSgRyqjKWVm+/XhWDIT5iMJZZ/IgmbICueaa7go8poHuTTyUDPHPIeL5d9Aru7qD4JtX+UVy6GYKhWx/guv+A7zyJ8d1kMLsmUAro80DLPDoais2I8YPpbu+xTSLLswIYddDdwg3P8mMAGzuWY/ZLumwpRr/fbI+t2Sm9KKGNGkGGIKAg43cs=
-----END PUBLIC KEY-----`
)

func TestSignatureAlgorithm(t *testing.T) {
	for _, test := range []struct {
		name   string
		keyPEM string
		want   SignatureAlgorithm
	}{
		{name: "ECDSA", keyPEM: ecdsaPublicKey, want: ECDSA},
		{name: "RSA", keyPEM: rsaPublicKey, want: RSA},
		{name: "DSA", keyPEM: dsaPublicKey, want: DSA},
	} {
		keyDER, _ := pem.Decode([]byte(test.keyPEM))
		key, err := x509.ParsePKIXPublicKey(keyDER.Bytes)
		if err != nil {
			t.Errorf("der: could not parse public key as PKIX (%v)", err)
			continue
		}

		if got := SignatureAlgorithmFromPubKey(key); got != test.want {
			t.Errorf("%v: SignatureAlgorithm() = %v, want %v", test.name, got, test.want)
		}
	}
}
