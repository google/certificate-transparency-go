// Copyright 2018 Google Inc. All Rights Reserved.
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
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/golang/mock/gomock"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/trillian/ctfe/configpb"
	"github.com/google/certificate-transparency-go/trillian/testdata"
	"github.com/google/trillian"
	"github.com/google/trillian/crypto/keys/pem"
	"github.com/miekg/dns"
)

type dnsTest struct {
	name      string
	zone      string
	setup     func(*handlerTestInfo)
	msg       *dns.Msg
	signErr   error
	wantRRs   int
	wantRcode int
	wantTxt   string
	wantTTL   uint32
}

func TestDNSHandler(t *testing.T) {
	ds := ct.DigitallySigned{
		Algorithm: tls.SignatureAndHashAlgorithm{Signature: tls.ECDSA, Hash: tls.SHA256},
		Signature: fakeSignature,
	}
	fakeSig, err := tls.Marshal(ds)
	if err != nil {
		t.Fatalf("Failed to marshal fake signature: %v", err)
	}

	goodSLR := &trillian.SignedLogRoot{
		TreeSize:       45678,
		RootHash:       []byte("89abcdef89abcdef89abcdef89abcdef"),
		TimestampNanos: 12345000000,
	}

	goodHash := base64.StdEncoding.EncodeToString(goodSLR.RootHash)

	badHashSLR := &trillian.SignedLogRoot{
		TreeSize:       45678,
		RootHash:       []byte("too short for a hash"),
		TimestampNanos: 12345000000,
	}

	goodCProof7 := &trillian.GetConsistencyProofResponse{
		Proof: makeProof(7),
	}

	// This proof is too large to fit in one response.
	goodCProof15 := &trillian.GetConsistencyProofResponse{
		Proof: makeProof(15),
	}

	goodIProof7 := &trillian.GetInclusionProofResponse{
		Proof: makeProof(7),
	}

	// This proof is too large to fit in one response.
	goodIProof15 := &trillian.GetInclusionProofResponse{
		Proof: makeProof(15),
	}

	hashResponse := &trillian.GetLeavesByHashResponse{Leaves: []*trillian.LogLeaf{{LeafIndex: 555741}}}

	tests := []dnsTest{
		// Tests for the STH query handler.
		{
			name: "STHBackendFail",
			zone: "good.ct.googleapis.com",
			msg:  &dns.Msg{Question: []dns.Question{{Name: "sth.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			setup: func(h *handlerTestInfo) {
				h.client.EXPECT().GetLatestSignedLogRoot(gomock.Any(), &trillian.GetLatestSignedLogRootRequest{LogId: 0x42}).Times(1).Return(nil, errors.New("get root failed"))
			},
			wantRcode: dns.RcodeServerFailure,
		},
		{
			name: "STHSignFail",
			zone: "good.ct.googleapis.com",
			msg:  &dns.Msg{Question: []dns.Question{{Name: "sth.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			setup: func(h *handlerTestInfo) {
				h.client.EXPECT().GetLatestSignedLogRoot(gomock.Any(), &trillian.GetLatestSignedLogRootRequest{LogId: 0x42}).Times(1).Return(nil, errors.New("get root failed"))
			},
			signErr:   errors.New("sign failed"),
			wantRcode: dns.RcodeServerFailure,
		},
		{
			name:      "STHBadQType",
			zone:      "good.ct.googleapis.com",
			msg:       &dns.Msg{Question: []dns.Question{{Name: "sth.good.ct.googleapis.com", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}}},
			wantRcode: dns.RcodeFormatError,
		},
		{
			name:      "STHBadQClass",
			zone:      "good.ct.googleapis.com",
			msg:       &dns.Msg{Question: []dns.Question{{Name: "sth.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassCHAOS}}},
			wantRcode: dns.RcodeFormatError,
		},
		{
			name:      "STHWrongZone",
			zone:      "good.ct.googleapis.com",
			msg:       &dns.Msg{Question: []dns.Question{{Name: "sth.bad.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			wantRcode: dns.RcodeNotZone,
		},
		{
			name: "STHBadHash",
			zone: "good.ct.googleapis.com",
			msg:  &dns.Msg{Question: []dns.Question{{Name: "sth.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			setup: func(h *handlerTestInfo) {
				h.client.EXPECT().GetLatestSignedLogRoot(gomock.Any(), &trillian.GetLatestSignedLogRootRequest{LogId: 0x42}).Times(1).Return(&trillian.GetLatestSignedLogRootResponse{SignedLogRoot: badHashSLR}, nil)
			},
			wantRcode: dns.RcodeServerFailure,
		},
		{
			name: "STH",
			zone: "good.ct.googleapis.com",
			msg:  &dns.Msg{Question: []dns.Question{{Name: "sth.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			setup: func(h *handlerTestInfo) {
				h.client.EXPECT().GetLatestSignedLogRoot(gomock.Any(), &trillian.GetLatestSignedLogRootRequest{LogId: 0x42}).Times(1).Return(&trillian.GetLatestSignedLogRootResponse{SignedLogRoot: goodSLR}, nil)
			},
			wantRRs: 1,
			wantTxt: fmt.Sprintf("45678.12345.%s.%s", goodHash, base64.StdEncoding.EncodeToString(fakeSig)),
			wantTTL: sthTTL,
		},
		// Tests for STH consistency handler.
		{
			name: "ConsistBackendFail",
			zone: "good.ct.googleapis.com",
			msg:  &dns.Msg{Question: []dns.Question{{Name: "0.123456.999999.sth-consistency.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			setup: func(h *handlerTestInfo) {
				h.client.EXPECT().GetConsistencyProof(gomock.Any(), &trillian.GetConsistencyProofRequest{LogId: 0x42, FirstTreeSize: 123456, SecondTreeSize: 999999}).Times(1).Return(nil, errors.New("get proof failed"))
			},
			wantRcode: dns.RcodeServerFailure,
		},
		{
			name: "ConsistStartOutOfRange",
			zone: "good.ct.googleapis.com",
			msg:  &dns.Msg{Question: []dns.Question{{Name: "7.123456.999999.sth-consistency.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			setup: func(h *handlerTestInfo) {
				h.client.EXPECT().GetConsistencyProof(gomock.Any(), &trillian.GetConsistencyProofRequest{LogId: 0x42, FirstTreeSize: 123456, SecondTreeSize: 999999}).Times(1).Return(goodCProof7, nil)
			},
			wantRcode: dns.RcodeServerFailure,
		},
		{
			name:      "ConsistMismatchRegex",
			zone:      "good.ct.googleapis.com",
			msg:       &dns.Msg{Question: []dns.Question{{Name: "=7.123456.999999.sth-consistency.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			wantRcode: dns.RcodeNotZone,
		},
		{
			name: "ConsistAllProofAndItFits",
			zone: "good.ct.googleapis.com",
			msg:  &dns.Msg{Question: []dns.Question{{Name: "0.123456.999999.sth-consistency.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			setup: func(h *handlerTestInfo) {
				h.client.EXPECT().GetConsistencyProof(gomock.Any(), &trillian.GetConsistencyProofRequest{LogId: 0x42, FirstTreeSize: 123456, SecondTreeSize: 999999}).Times(1).Return(goodCProof7, nil)
			},
			wantRRs: 1,
			wantTxt: expectProof(0, 7),
			wantTTL: respTTL,
		},
		{
			name: "ConsistPartialProofAndItFits",
			zone: "good.ct.googleapis.com",
			msg:  &dns.Msg{Question: []dns.Question{{Name: "3.123456.999999.sth-consistency.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			setup: func(h *handlerTestInfo) {
				h.client.EXPECT().GetConsistencyProof(gomock.Any(), &trillian.GetConsistencyProofRequest{LogId: 0x42, FirstTreeSize: 123456, SecondTreeSize: 999999}).Times(1).Return(goodCProof7, nil)
			},
			wantRRs: 1,
			wantTxt: expectProof(3, 7),
			wantTTL: respTTL,
		},
		{
			name: "ConsistProofTruncated",
			zone: "good.ct.googleapis.com",
			msg:  &dns.Msg{Question: []dns.Question{{Name: "0.123456.999999.sth-consistency.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			setup: func(h *handlerTestInfo) {
				h.client.EXPECT().GetConsistencyProof(gomock.Any(), &trillian.GetConsistencyProofRequest{LogId: 0x42, FirstTreeSize: 123456, SecondTreeSize: 999999}).Times(1).Return(goodCProof15, nil)
			},
			wantRRs: 1,
			wantTxt: expectProof(0, 7),
			wantTTL: respTTL,
		},
		{
			name: "ConsistRestOfProofTruncated",
			zone: "good.ct.googleapis.com",
			msg:  &dns.Msg{Question: []dns.Question{{Name: "8.123456.999999.sth-consistency.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			setup: func(h *handlerTestInfo) {
				h.client.EXPECT().GetConsistencyProof(gomock.Any(), &trillian.GetConsistencyProofRequest{LogId: 0x42, FirstTreeSize: 123456, SecondTreeSize: 999999}).Times(1).Return(goodCProof15, nil)
			},
			wantRRs: 1,
			wantTxt: expectProof(8, 15),
			wantTTL: respTTL,
		},
		{
			name:      "ConsistNotOurZone",
			zone:      "good.ct.googleapis.com",
			msg:       &dns.Msg{Question: []dns.Question{{Name: "8.123456.999999.sth-consistency.notgood.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			wantRcode: dns.RcodeNotZone,
		},
		// Tests for the Hash handler. The base32 string is "hello1hello2hello3",
		// length 18 bytes to match the size of an encoded Merkle Leaf.
		{
			name: "HashBackendFail",
			zone: "good.ct.googleapis.com",
			msg:  &dns.Msg{Question: []dns.Question{{Name: "NBSWY3DPGFUGK3DMN4ZGQZLMNRXTG.hash.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			setup: func(h *handlerTestInfo) {
				h.client.EXPECT().GetLeavesByHash(gomock.Any(), &trillian.GetLeavesByHashRequest{LogId: 0x42, LeafHash: [][]byte{[]byte("hello1hello2hello3")}}).Times(1).Return(nil, errors.New("get root failed"))
			},
			wantRcode: dns.RcodeServerFailure,
		},
		{
			// For this test the input matches the base32 regex but does not decode
			// because it's an incomplete group.
			name:      "HashBase32BadDecode",
			zone:      "good.ct.googleapis.com",
			msg:       &dns.Msg{Question: []dns.Question{{Name: "NBSWY3DPGFUGK3DMN4ZGQZ.hash.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			wantRcode: dns.RcodeServerFailure,
		},
		{
			name: "HashBackendNoLeaves",
			zone: "good.ct.googleapis.com",
			msg:  &dns.Msg{Question: []dns.Question{{Name: "NBSWY3DPGFUGK3DMN4ZGQZLMNRXTG.hash.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			setup: func(h *handlerTestInfo) {
				h.client.EXPECT().GetLeavesByHash(gomock.Any(), &trillian.GetLeavesByHashRequest{LogId: 0x42, LeafHash: [][]byte{[]byte("hello1hello2hello3")}}).Times(1).Return(&trillian.GetLeavesByHashResponse{}, nil)
			},
			wantRcode: dns.RcodeServerFailure,
		},
		{
			name: "HashOK",
			zone: "good.ct.googleapis.com",
			msg:  &dns.Msg{Question: []dns.Question{{Name: "NBSWY3DPGFUGK3DMN4ZGQZLMNRXTG.hash.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			setup: func(h *handlerTestInfo) {
				h.client.EXPECT().GetLeavesByHash(gomock.Any(), &trillian.GetLeavesByHashRequest{LogId: 0x42, LeafHash: [][]byte{[]byte("hello1hello2hello3")}}).Times(1).Return(hashResponse, nil)
			},
			wantRRs: 1,
			wantTxt: "555741",
			wantTTL: respTTL,
		},
		{
			name:      "HashNotOurZone",
			zone:      "good.ct.googleapis.com",
			msg:       &dns.Msg{Question: []dns.Question{{Name: "NBSWY3DPGFUGK3DMN4ZGQZLMNRXTG.hash.notgood.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			wantRcode: dns.RcodeNotZone,
		},
		// Tests for the Tree handler.
		{
			name: "TreeBackendFail",
			zone: "good.ct.googleapis.com",
			msg:  &dns.Msg{Question: []dns.Question{{Name: "0.123456.999999.tree.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			setup: func(h *handlerTestInfo) {
				h.client.EXPECT().GetInclusionProof(gomock.Any(), &trillian.GetInclusionProofRequest{LogId: 0x42, LeafIndex: 123456, TreeSize: 999999}).Times(1).Return(nil, errors.New("get proof failed"))
			},
			wantRcode: dns.RcodeServerFailure,
		},
		{
			name: "TreeStartOutOfRange",
			zone: "good.ct.googleapis.com",
			msg:  &dns.Msg{Question: []dns.Question{{Name: "7.123456.999999.tree.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			setup: func(h *handlerTestInfo) {
				h.client.EXPECT().GetInclusionProof(gomock.Any(), &trillian.GetInclusionProofRequest{LogId: 0x42, LeafIndex: 123456, TreeSize: 999999}).Times(1).Return(goodIProof7, nil)
			},
			wantRcode: dns.RcodeServerFailure,
		},
		{
			name:      "TreeMismatchRegex",
			zone:      "good.ct.googleapis.com",
			msg:       &dns.Msg{Question: []dns.Question{{Name: "=7.123456.999999.tree.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			wantRcode: dns.RcodeNotZone,
		},
		{
			name: "TreeAllProofAndItFits",
			zone: "good.ct.googleapis.com",
			msg:  &dns.Msg{Question: []dns.Question{{Name: "0.123456.999999.tree.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			setup: func(h *handlerTestInfo) {
				h.client.EXPECT().GetInclusionProof(gomock.Any(), &trillian.GetInclusionProofRequest{LogId: 0x42, LeafIndex: 123456, TreeSize: 999999}).Times(1).Return(goodIProof7, nil)
			},
			wantRRs: 1,
			wantTxt: expectProof(0, 7),
			wantTTL: respTTL,
		},
		{
			name: "TreePartialProofAndItFits",
			zone: "good.ct.googleapis.com",
			msg:  &dns.Msg{Question: []dns.Question{{Name: "3.123456.999999.tree.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			setup: func(h *handlerTestInfo) {
				h.client.EXPECT().GetInclusionProof(gomock.Any(), &trillian.GetInclusionProofRequest{LogId: 0x42, LeafIndex: 123456, TreeSize: 999999}).Times(1).Return(goodIProof7, nil)
			},
			wantRRs: 1,
			wantTxt: expectProof(3, 7),
			wantTTL: respTTL,
		},
		{
			name: "TreeProofTruncated",
			zone: "good.ct.googleapis.com",
			msg:  &dns.Msg{Question: []dns.Question{{Name: "0.123456.999999.tree.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			setup: func(h *handlerTestInfo) {
				h.client.EXPECT().GetInclusionProof(gomock.Any(), &trillian.GetInclusionProofRequest{LogId: 0x42, LeafIndex: 123456, TreeSize: 999999}).Times(1).Return(goodIProof15, nil)
			},
			wantRRs: 1,
			wantTxt: expectProof(0, 7),
			wantTTL: respTTL,
		},
		{
			name: "TreeRestOfProofTruncated",
			zone: "good.ct.googleapis.com",
			msg:  &dns.Msg{Question: []dns.Question{{Name: "8.123456.999999.tree.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			setup: func(h *handlerTestInfo) {
				h.client.EXPECT().GetInclusionProof(gomock.Any(), &trillian.GetInclusionProofRequest{LogId: 0x42, LeafIndex: 123456, TreeSize: 999999}).Times(1).Return(goodIProof15, nil)
			},
			wantRRs: 1,
			wantTxt: expectProof(8, 15),
			wantTTL: respTTL,
		},
		{
			name:      "TreeNotOurZone",
			zone:      "good.ct.googleapis.com",
			msg:       &dns.Msg{Question: []dns.Question{{Name: "0.123456.999999.tree.notgood.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			wantRcode: dns.RcodeNotZone,
		},
		// General tests
		{
			name:      "NotValidQuery",
			zone:      "good.ct.googleapis.com",
			msg:       &dns.Msg{Question: []dns.Question{{Name: "randomstuff.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			wantRcode: dns.RcodeNotZone,
		},
		{
			name:      "NotOurZone",
			zone:      "good.ct.googleapis2.com",
			msg:       &dns.Msg{Question: []dns.Question{{Name: "sth.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			wantRcode: dns.RcodeNotZone,
		},
	}

	key, err := pem.UnmarshalPublicKey(testdata.DemoPublicKey)
	if err != nil {
		t.Fatalf("Failed to load public key: %v", err)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var signer crypto.Signer
			if test.signErr != nil {
				signer = testdata.NewSignerWithErr(key, test.signErr)
			} else {
				signer = testdata.NewSignerWithFixedSig(key, fakeSignature)
			}

			info := setupTest(t, nil, signer)
			if test.setup != nil {
				test.setup(&info)
			}
			cfg := new(configpb.LogConfig)
			cfg.LogId = 0x42
			cfg.DnsZone = test.zone

			d := NewDNS(cfg, info.c)
			frw := fakeResponseWriter{}
			d.ServeDNS(&frw, test.msg)

			// We should always get a single message written to the response writer.
			// It should always be an INET class and TXT type. The Query should have
			// been copied from the request. There should be 1 RR response in the
			// result, unless we expected an error.
			if len(frw.messages) != 1 {
				t.Fatalf("got: %d msgs written, want: 1", len(frw.messages))
			}

			if got, want := frw.messages[0].Rcode, test.wantRcode; got != want {
				t.Errorf("got Rcode: %d, want: %d", got, want)
			}

			if got, want := frw.messages[0].Question[0].Name, test.msg.Question[0].Name; got != want {
				t.Errorf("got question: %v, want: %v", got, want)
			}

			if got, want := len(frw.messages[0].Answer), test.wantRRs; got != want {
				t.Fatalf("got: %d RRs in response, want: %d", got, want)
			}
			if test.wantRRs != 0 {
				answer := frw.messages[0].Answer[0]
				if got, want := answer.Header().Class, dns.ClassINET; got != uint16(want) {
					t.Errorf("got RR class: %d in response, want: INET(%d)", got, want)
				}
				if got, want := answer.Header().Rrtype, dns.TypeTXT; got != want {
					t.Errorf("got RR type: %d in response, want: TXT(%d)", got, want)
				}
				if got, want := answer.Header().Ttl, test.wantTTL; got != want {
					t.Errorf("got TTL: %d in response, want: %d", got, want)
				}
				if len(test.wantTxt) != 0 {
					rr := answer.(*dns.TXT)
					if len(rr.Txt) != 1 {
						t.Errorf("got %d TXT responses in Answer, want: 1", len(rr.Txt))
					}
					if got, want := rr.Txt[0], test.wantTxt; got != want {
						t.Errorf("got TXT response: %s, want: %s", got, want)
					}
				}
			}

			info.mockCtrl.Finish()
		})
	}
}

func makeProof(l int) *trillian.Proof {
	p := &trillian.Proof{}
	for i := 0; i < l; i++ {
		input := []byte(fmt.Sprintf("hash%d", i))
		hash := sha256.Sum256(input)
		p.Hashes = append(p.Hashes, hash[:])
	}
	return p
}

func expectProof(s, l int) string {
	p := make([]byte, 0, maxProofLen)
	for i := s; i < l; i++ {
		input := []byte(fmt.Sprintf("hash%d", i))
		hash := sha256.Sum256(input)
		p = append(p, hash[:]...)
	}
	return string(p)
}

type fakeResponseWriter struct {
	writeErr error
	messages []*dns.Msg
}

func (f fakeResponseWriter) LocalAddr() net.Addr {
	return nil
}

func (f fakeResponseWriter) RemoteAddr() net.Addr {
	return nil
}

func (f *fakeResponseWriter) WriteMsg(m *dns.Msg) error {
	f.messages = append(f.messages, m)
	return f.writeErr
}

func (f *fakeResponseWriter) Write([]byte) (int, error) {
	return 0, errors.New("not expecting Write() calls")
}

func (f fakeResponseWriter) Close() error {
	return nil
}

func (f fakeResponseWriter) TsigStatus() error {
	return nil
}

func (f fakeResponseWriter) TsigTimersOnly(bool) {
}

func (f fakeResponseWriter) Hijack() {
}
