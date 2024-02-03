// Copyright 2024 Google LLC. All Rights Reserved.
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

package x509

import (
	"testing"
)

func FuzzParseECPrivateKeyTest(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseECPrivateKey(data)
	})
}

func FuzzParsePKIXPublicKeyTest(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParsePKIXPublicKey(data)
	})
}

func FuzzParseTBSCertificateTest(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseTBSCertificate(data)
	})
}

func FuzzParseCertificateTest(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseCertificate(data)
	})
}

func FuzzParseCertificatesTest(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseCertificates(data)
	})
}

func FuzzParseCRLTest(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseCRL(data)
	})
}

func FuzzParseDERCRLTest(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseDERCRL(data)
	})
}

func FuzzParseCertificateRequestTest(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseCertificateRequest(data)
	})
}

func FuzzParsePKCS8PrivateKeyest(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParsePKCS8PrivateKey(data)
	})
}

func FuzzParsePKCS1PrivateKeyTest(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParsePKCS1PrivateKey(data)
	})
}

func FuzzParsePKCS1PublicKeyTest(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParsePKCS1PublicKey(data)
	})
}

func FuzzParseCertificateListTest(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseCertificateList(data)
	})
}

func FuzzParseCertificateListDERTest(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseCertificateListDER(data)
	})
}
