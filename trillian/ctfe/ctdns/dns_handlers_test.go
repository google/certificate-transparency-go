// Copyright 2018 Google LLC. All Rights Reserved.
//
// ￼Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// ￼You may obtain a copy of the License at
// ￼
// ￼     http://www.apache.org/licenses/LICENSE-2.0
// ￼
// ￼Unless required by applicable law or agreed to in writing, software
// ￼distributed under the License is distributed on an "AS IS" BASIS,
// ￼WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// ￼See the License for the specific language governing permissions and
// ￼limitations under the License.

package ctdns

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/trillian/ctfe/configpb"
	"github.com/google/certificate-transparency-go/trillian/ctfe/ctdns/mockclient"
	"github.com/miekg/dns"
)

type dnsTest struct {
	name      string
	zone      string
	setup     func(client *mockclient.MockDNSLogClient)
	msg       *dns.Msg
	wantRRs   int
	wantRcode int
	wantTxt   string
	wantTTL   uint32
	// the following are used by HTTP tests only
	prefix string
	paths  []httpPath
	rsps   []string
}

type httpPath struct {
	path   string
	params map[string]string
}

var (
	jsonSTH = `{
    "tree_size":4364451528,
    "timestamp":1526459210436,
    "sha256_root_hash":"WAJcIzHSrWNayb7driAW+z9V10rjpVlAvbjwvQPkwsY=",
    "tree_head_signature":"BAMARzBFAiAK9kjKAdwYpgCXr7blk9rGceoH0ll2MDMs6Vptby0CLQIhAN0WhMQGjvRpmCy7cBGp1CbtMi8090ZDqyFSxKHh5X4B"
  }`

	jsonSTH1234568 = `{
    "tree_size":1234568,
    "timestamp":1526459210436,
    "sha256_root_hash":"WAJcIzHSrWNayb7driAW+z9V10rjpVlAvbjwvQPkwsY=",
    "tree_head_signature":"BAMARzBFAiAK9kjKAdwYpgCXr7blk9rGceoH0ll2MDMs6Vptby0CLQIhAN0WhMQGjvRpmCy7cBGp1CbtMi8090ZDqyFSxKHh5X4B"
  }`

	jsonSTHConsistency = `{
  "consistency":[
    "D0mGIT551g4oH1guG4m4twfHdfr5bBXTrWt4j4Wmv5g=",
    "D2jUPH4Suig73rU7h8XdRzbvHkLtIHYAU0KQ8D08ZrM=",
    "aOosnhozBi5dWL1A7EK+DnxOqPYzwios+9iZO+CL7r8=",
    "G1yEs838pbU/SdpkL8+7uUmUcWLwb9j87FzEPp/ILzk=",
    "ZdyLcD/q7sF6mCK1Zu3Rnj8FNNPZimIkBdnG13++cc0=",
    "pS7KloJ9rWc6PFna+XY6xhdF2BcT6ktWt5IwP5qTe+g=",
    "riS44j21/liON/iIE3nZqtHH8iDLyEwQ0q4Uqt4Dckc=",
    "2+CGk9TmxHvqatCI+YPhGjNRPgihx/40hN8pzboxejw=",
    "D8//xQaOKFsf6DfH9cwXd9qzZiuRlpHU+i734BpGhkM=",
    "Jdz/9QG1MjRZt4wCgmNR/Hjwfsw9+0LhIWFvHldYYS0=",
    "phbVuvDGxLGpdUrnwb57bmEqC0hvJiGwQzaEKs1Lz6o=",
    "27Vc+jGfBtEVQZ97uPtcYuHY3lk+7c46TA8sO3X5TMw=",
    "IuLIszkSOAQBjRN8jFAghsBZzsjYNeDdPuIMX0ZH8FQ=",
    "dOKdoH8yEw23pbS4+YIrkjA/L+2AdufVguhgegJ3Hj0=",
    "eYO3mmuEqS4NppWOWvRnyzm6ZKpNva1CMeq2bL2fE1g=",
    "ByJJfvMgaUWdMSaGgp6DDpl8fEvMW/YWt8ncD7AYqR8=",
    "gjY6Uzv54IZovvmNZgjIZ9byPjC/vRFGWPmpfZbLIvo=",
    "cKJjufogFybFdgDCXAxo6GR9WNnjELvME4uTpE045ss=",
    "SYYxuh1mExXqWN03/uOd4BYPcYPWjqsL492n25jjvjg=",
    "ghO5QJoRKfOh54ATye6uBhBqPROovRYnf/e5mIo6Y+E=",
    "zYvOytAG/PS+96Qmtts0DCIkA/1y5aCgYnQB883dMDE=",
    "DZFH5Kir5u8h8nTkTm0UMCO4o0zk8mv5X/NPFbbTkoo=",
    "tnJwlRsELZSouqhctbbirkshD0Rvg6qjipLdM1RzkHc="]
  }`

	jsonProofByHash = `{
    "leaf_index":1234567,
    "audit_path":[
      "D0mGIT551g4oH1guG4m4twfHdfr5bBXTrWt4j4Wmv5g=",
      "aOosnhozBi5dWL1A7EK+DnxOqPYzwios+9iZO+CL7r8=",
      "G1yEs838pbU/SdpkL8+7uUmUcWLwb9j87FzEPp/ILzk=",
      "D8//xQaOKFsf6DfH9cwXd9qzZiuRlpHU+i734BpGhkM=",
      "phbVuvDGxLGpdUrnwb57bmEqC0hvJiGwQzaEKs1Lz6o=",
      "27Vc+jGfBtEVQZ97uPtcYuHY3lk+7c46TA8sO3X5TMw=",
      "dOKdoH8yEw23pbS4+YIrkjA/L+2AdufVguhgegJ3Hj0=",
      "ByJJfvMgaUWdMSaGgp6DDpl8fEvMW/YWt8ncD7AYqR8=",
      "gjY6Uzv54IZovvmNZgjIZ9byPjC/vRFGWPmpfZbLIvo=",
      "SYYxuh1mExXqWN03/uOd4BYPcYPWjqsL492n25jjvjg=",
      "DZFH5Kir5u8h8nTkTm0UMCO4o0zk8mv5X/NPFbbTkoo="]
    }`

	jsonEntryAndProof = `{
    "leaf_input":"",
    "audit_path":[
      "D0mGIT551g4oH1guG4m4twfHdfr5bBXTrWt4j4Wmv5g=",
      "aOosnhozBi5dWL1A7EK+DnxOqPYzwios+9iZO+CL7r8=",
      "G1yEs838pbU/SdpkL8+7uUmUcWLwb9j87FzEPp/ILzk=",
      "D8//xQaOKFsf6DfH9cwXd9qzZiuRlpHU+i734BpGhkM=",
      "phbVuvDGxLGpdUrnwb57bmEqC0hvJiGwQzaEKs1Lz6o=",
      "27Vc+jGfBtEVQZ97uPtcYuHY3lk+7c46TA8sO3X5TMw=",
      "dOKdoH8yEw23pbS4+YIrkjA/L+2AdufVguhgegJ3Hj0=",
      "ByJJfvMgaUWdMSaGgp6DDpl8fEvMW/YWt8ncD7AYqR8=",
      "gjY6Uzv54IZovvmNZgjIZ9byPjC/vRFGWPmpfZbLIvo=",
      "SYYxuh1mExXqWN03/uOd4BYPcYPWjqsL492n25jjvjg=",
      "DZFH5Kir5u8h8nTkTm0UMCO4o0zk8mv5X/NPFbbTkoo="]
    }`
)

func TestDNSHandler(t *testing.T) {
	hash := ct.SHA256Hash{}
	if hash.FromBase64String("hGQ56tGHFO8q9K7O9uV2WKv0tB6ZoMaTS+1ReHKnwB4=") != nil {
		t.Fatalf("Failed to parse hash")
	}

	goodSTH := &ct.SignedTreeHead{
		TreeSize:       45678,
		SHA256RootHash: hash,
		Timestamp:      12345,
		TreeHeadSignature: ct.DigitallySigned{
			Signature: []byte("test"),
		},
	}

	mSig, err := tls.Marshal(goodSTH.TreeHeadSignature)
	if err != nil {
		t.Fatalf("Failed to marshal signature")
	}

	tests := []dnsTest{
		// Tests for the STH query handler.
		{
			name: "STHBackendFail",
			zone: "good.ct.googleapis.com",
			msg:  &dns.Msg{Question: []dns.Question{{Name: "sth.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			setup: func(c *mockclient.MockDNSLogClient) {
				c.EXPECT().GetSTH(gomock.Any()).Times(1).Return(nil, errors.New("get root failed"))
			},
			wantRcode: dns.RcodeServerFailure,
		},
		{
			name:      "STHBadQType",
			zone:      "good.ct.googleapis.com",
			msg:       &dns.Msg{Question: []dns.Question{{Name: "sth.good.ct.googleapis.com", Qtype: dns.TypeA, Qclass: dns.ClassINET}}},
			wantRcode: dns.RcodeSuccess,
		},
		{
			name:      "STHBadQClass",
			zone:      "good.ct.googleapis.com",
			msg:       &dns.Msg{Question: []dns.Question{{Name: "sth.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassCHAOS}}},
			wantRcode: dns.RcodeSuccess,
		},
		{
			name:      "STHWrongZone",
			zone:      "good.ct.googleapis.com",
			msg:       &dns.Msg{Question: []dns.Question{{Name: "sth.bad.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			wantRcode: dns.RcodeNotZone,
		},
		{
			name: "STH",
			zone: "good.ct.googleapis.com",
			msg:  &dns.Msg{Question: []dns.Question{{Name: "sth.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			setup: func(c *mockclient.MockDNSLogClient) {
				c.EXPECT().GetSTH(gomock.Any()).Times(1).Return(goodSTH, nil)
			},
			wantRRs: 1,
			wantTxt: fmt.Sprintf("45678.12345.%s.%s", base64.StdEncoding.EncodeToString(hash[:]), base64.StdEncoding.EncodeToString(mSig)),
			wantTTL: sthTTL,
		},
		{
			name: "CaseInsensitiveSTH",
			zone: "good.ct.googleapis.com",
			msg:  &dns.Msg{Question: []dns.Question{{Name: "StH.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			setup: func(c *mockclient.MockDNSLogClient) {
				c.EXPECT().GetSTH(gomock.Any()).Times(1).Return(goodSTH, nil)
			},
			wantRRs: 1,
			wantTxt: fmt.Sprintf("45678.12345.%s.%s", base64.StdEncoding.EncodeToString(hash[:]), base64.StdEncoding.EncodeToString(mSig)),
			wantTTL: sthTTL,
		},
		// Tests for STH consistency handler.
		{
			name: "ConsistBackendFail",
			zone: "good.ct.googleapis.com",
			msg:  &dns.Msg{Question: []dns.Question{{Name: "0.123456.999999.sth-consistency.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			setup: func(c *mockclient.MockDNSLogClient) {
				c.EXPECT().GetSTHConsistency(gomock.Any(), uint64(123456), uint64(999999)).Times(1).Return(nil, errors.New("get proof failed"))
			},
			wantRcode: dns.RcodeServerFailure,
		},
		{
			name: "ConsistStartOutOfRange",
			zone: "good.ct.googleapis.com",
			msg:  &dns.Msg{Question: []dns.Question{{Name: "7.123456.999999.sth-consistency.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			setup: func(c *mockclient.MockDNSLogClient) {
				c.EXPECT().GetSTHConsistency(gomock.Any(), uint64(123456), uint64(999999)).Times(1).Return(makeProof(7), nil)
			},
			wantRcode: dns.RcodeServerFailure,
		},
		{
			name:      "ConsistMismatchRegex",
			zone:      "good.ct.googleapis.com",
			msg:       &dns.Msg{Question: []dns.Question{{Name: "=7.123456.999999.sth-consistency.notgood.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			wantRcode: dns.RcodeNotZone,
		},
		{
			name: "ConsistAllProofAndItFits",
			zone: "good.ct.googleapis.com",
			msg:  &dns.Msg{Question: []dns.Question{{Name: "0.123456.999999.sth-consistency.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			setup: func(c *mockclient.MockDNSLogClient) {
				c.EXPECT().GetSTHConsistency(gomock.Any(), uint64(123456), uint64(999999)).Times(1).Return(makeProof(7), nil)
			},
			wantRRs: 1,
			wantTxt: expectProof(0, 7),
			wantTTL: respTTL,
		},
		{
			name: "CaseInsensitiveConsist",
			zone: "good.ct.googleapis.com",
			msg:  &dns.Msg{Question: []dns.Question{{Name: "0.123456.999999.StH-ConsiSTencY.gooD.CT.googleAPIs.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			setup: func(c *mockclient.MockDNSLogClient) {
				c.EXPECT().GetSTHConsistency(gomock.Any(), uint64(123456), uint64(999999)).Times(1).Return(makeProof(7), nil)
			},
			wantRRs: 1,
			wantTxt: expectProof(0, 7),
			wantTTL: respTTL,
		},
		{
			name: "ConsistPartialProofAndItFits",
			zone: "good.ct.googleapis.com",
			msg:  &dns.Msg{Question: []dns.Question{{Name: "3.123456.999999.sth-consistency.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			setup: func(c *mockclient.MockDNSLogClient) {
				c.EXPECT().GetSTHConsistency(gomock.Any(), uint64(123456), uint64(999999)).Times(1).Return(makeProof(7), nil)
			},
			wantRRs: 1,
			wantTxt: expectProof(3, 7),
			wantTTL: respTTL,
		},
		{
			name: "ConsistProofTruncated",
			zone: "good.ct.googleapis.com",
			msg:  &dns.Msg{Question: []dns.Question{{Name: "0.123456.999999.sth-consistency.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			setup: func(c *mockclient.MockDNSLogClient) {
				c.EXPECT().GetSTHConsistency(gomock.Any(), uint64(123456), uint64(999999)).Times(1).Return(makeProof(15), nil)
			},
			wantRRs: 1,
			wantTxt: expectProof(0, 7),
			wantTTL: respTTL,
		},
		{
			name: "ConsistRestOfProofTruncated",
			zone: "good.ct.googleapis.com",
			msg:  &dns.Msg{Question: []dns.Question{{Name: "8.123456.999999.sth-consistency.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			setup: func(c *mockclient.MockDNSLogClient) {
				c.EXPECT().GetSTHConsistency(gomock.Any(), uint64(123456), uint64(999999)).Times(1).Return(makeProof(15), nil)
			},
			wantRRs: 1,
			wantTxt: expectProof(8, 15),
			wantTTL: respTTL,
		},
		{
			name:      "ConsistOnly",
			zone:      "good.ct.googleapis.com",
			msg:       &dns.Msg{Question: []dns.Question{{Name: "sth-consistency.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			wantRcode: dns.RcodeSuccess,
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
			name: "HashBackendSTHFail",
			zone: "good.ct.googleapis.com",
			msg:  &dns.Msg{Question: []dns.Question{{Name: "NBSWY3DPGFUGK3DMN4ZGQZLMNRXTG.hash.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			setup: func(c *mockclient.MockDNSLogClient) {
				c.EXPECT().GetSTH(gomock.Any()).Times(1).Return(nil, errors.New("it didn't work"))
			},
			wantRcode: dns.RcodeServerFailure,
		},
		{
			name: "HashBackendGetFail",
			zone: "good.ct.googleapis.com",
			msg:  &dns.Msg{Question: []dns.Question{{Name: "NBSWY3DPGFUGK3DMN4ZGQZLMNRXTG.hash.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			setup: func(c *mockclient.MockDNSLogClient) {
				gomock.InOrder(
					c.EXPECT().GetSTH(gomock.Any()).Times(1).Return(goodSTH, nil),
					c.EXPECT().GetProofByHash(gomock.Any(), []byte("hello1hello2hello3"), uint64(45678)).Times(1).Return(nil, errors.New("get proof failed")),
				)
			},
			wantRcode: dns.RcodeServerFailure,
		},
		{
			// For this test the input matches the base32 regex but does not decode
			// because it's an incomplete group.
			name:      "HashBase32BadLength",
			zone:      "good.ct.googleapis.com",
			msg:       &dns.Msg{Question: []dns.Question{{Name: "NBSWY3DPGFUGK3DMN4ZGQZ.hash.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			wantRcode: dns.RcodeNameError,
		},
		{
			// For this test the input matches the base32 regex but does not decode
			// because it's an incomplete group.
			name:      "HashNotBase32",
			zone:      "good.ct.googleapis.com",
			msg:       &dns.Msg{Question: []dns.Question{{Name: "/$!%/.hash.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			wantRcode: dns.RcodeNameError,
		},
		{
			name:      "HashOnly",
			zone:      "good.ct.googleapis.com",
			msg:       &dns.Msg{Question: []dns.Question{{Name: "hash.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			wantRcode: dns.RcodeSuccess,
		},
		{
			name: "HashOK",
			zone: "good.ct.googleapis.com",
			msg:  &dns.Msg{Question: []dns.Question{{Name: "NBSWY3DPGFUGK3DMN4ZGQZLMNRXTG.hash.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			setup: func(c *mockclient.MockDNSLogClient) {
				gomock.InOrder(
					c.EXPECT().GetSTH(gomock.Any()).Times(1).Return(goodSTH, nil),
					c.EXPECT().GetProofByHash(gomock.Any(), []byte("hello1hello2hello3"), uint64(45678)).Times(1).Return(&ct.GetProofByHashResponse{LeafIndex: 555741, AuditPath: [][]byte{}}, nil),
				)
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
			setup: func(c *mockclient.MockDNSLogClient) {
				c.EXPECT().GetEntryAndProof(gomock.Any(), uint64(123456), uint64(999999)).Times(1).Return(nil, errors.New("get proof failed"))
			},
			wantRcode: dns.RcodeServerFailure,
		},
		{
			name: "TreeStartOutOfRange",
			zone: "good.ct.googleapis.com",
			msg:  &dns.Msg{Question: []dns.Question{{Name: "7.123456.999999.tree.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			setup: func(c *mockclient.MockDNSLogClient) {
				c.EXPECT().GetEntryAndProof(gomock.Any(), uint64(123456), uint64(999999)).Times(1).Return(&ct.GetEntryAndProofResponse{AuditPath: makeProof(7)}, nil)
			},
			wantRcode: dns.RcodeServerFailure,
		},
		{
			name:      "TreeMismatchRegex",
			zone:      "good.ct.googleapis.com",
			msg:       &dns.Msg{Question: []dns.Question{{Name: "=7.123456.999999.tree.notgood.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			wantRcode: dns.RcodeNotZone,
		},
		{
			name: "TreeAllProofAndItFits",
			zone: "good.ct.googleapis.com",
			msg:  &dns.Msg{Question: []dns.Question{{Name: "0.123456.999999.tree.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			setup: func(c *mockclient.MockDNSLogClient) {
				c.EXPECT().GetEntryAndProof(gomock.Any(), uint64(123456), uint64(999999)).Times(1).Return(&ct.GetEntryAndProofResponse{AuditPath: makeProof(7)}, nil)
			},
			wantRRs: 1,
			wantTxt: expectProof(0, 7),
			wantTTL: respTTL,
		},
		{
			name: "TreePartialProofAndItFits",
			zone: "good.ct.googleapis.com",
			msg:  &dns.Msg{Question: []dns.Question{{Name: "3.123456.999999.tree.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			setup: func(c *mockclient.MockDNSLogClient) {
				c.EXPECT().GetEntryAndProof(gomock.Any(), uint64(123456), uint64(999999)).Times(1).Return(&ct.GetEntryAndProofResponse{AuditPath: makeProof(7)}, nil)
			},
			wantRRs: 1,
			wantTxt: expectProof(3, 7),
			wantTTL: respTTL,
		},
		{
			name: "TreeProofTruncated",
			zone: "good.ct.googleapis.com",
			msg:  &dns.Msg{Question: []dns.Question{{Name: "0.123456.999999.tree.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			setup: func(c *mockclient.MockDNSLogClient) {
				c.EXPECT().GetEntryAndProof(gomock.Any(), uint64(123456), uint64(999999)).Times(1).Return(&ct.GetEntryAndProofResponse{AuditPath: makeProof(15)}, nil)
			},
			wantRRs: 1,
			wantTxt: expectProof(0, 7),
			wantTTL: respTTL,
		},
		{
			name: "TreeRestOfProofTruncated",
			zone: "good.ct.googleapis.com",
			msg:  &dns.Msg{Question: []dns.Question{{Name: "8.123456.999999.tree.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			setup: func(c *mockclient.MockDNSLogClient) {
				c.EXPECT().GetEntryAndProof(gomock.Any(), uint64(123456), uint64(999999)).Times(1).Return(&ct.GetEntryAndProofResponse{AuditPath: makeProof(15)}, nil)
			},
			wantRRs: 1,
			wantTxt: expectProof(8, 15),
			wantTTL: respTTL,
		},
		{
			name:      "TreeOnly",
			zone:      "good.ct.googleapis.com",
			msg:       &dns.Msg{Question: []dns.Question{{Name: "tree.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			wantRcode: dns.RcodeSuccess,
		},
		{
			name:      "TreeSizeOnly",
			zone:      "good.ct.googleapis.com",
			msg:       &dns.Msg{Question: []dns.Question{{Name: "23.tree.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			wantRcode: dns.RcodeSuccess,
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
			wantRcode: dns.RcodeSuccess,
		},
		{
			name:      "NotOurZone",
			zone:      "good.ct.googleapis2.com",
			msg:       &dns.Msg{Question: []dns.Question{{Name: "sth.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			wantRcode: dns.RcodeNotZone,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			mc := mockclient.NewMockDNSLogClient(ctrl)
			if test.setup != nil {
				test.setup(mc)
			}
			cfg := new(configpb.LogConfig)
			cfg.LogId = 0x42
			cfg.DnsZone = test.zone

			// These tests use mocks and don't make actual HTTP requests.
			d := New(cfg, "http://localhost:2112", mc, time.Second*5)
			frw := fakeResponseWriter{}
			d.ServeDNS(&frw, test.msg)

			if err := checkResponse(frw, test); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestDNSHandlerHTTP(t *testing.T) {
	var consist ct.GetSTHConsistencyResponse
	if json.Unmarshal([]byte(jsonSTHConsistency), &consist) != nil {
		t.Fatalf("Failed to unmarshal sth consistency proof")
	}

	var proof ct.GetEntryAndProofResponse
	if json.Unmarshal([]byte(jsonEntryAndProof), &proof) != nil {
		t.Fatalf("Failed to unmarshal entry and proof")
	}

	tests := []dnsTest{
		{
			name:    "STH",
			zone:    "good.ct.googleapis.com",
			prefix:  "gooder",
			paths:   []httpPath{{path: "/gooder/ct/v1/get-sth"}},
			rsps:    []string{jsonSTH},
			msg:     &dns.Msg{Question: []dns.Question{{Name: "sth.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			wantRRs: 1,
			wantTxt: "4364451528.1526459210436.WAJcIzHSrWNayb7driAW+z9V10rjpVlAvbjwvQPkwsY=.BAMARzBFAiAK9kjKAdwYpgCXr7blk9rGceoH0ll2MDMs6Vptby0CLQIhAN0WhMQGjvRpmCy7cBGp1CbtMi8090ZDqyFSxKHh5X4B",
			wantTTL: sthTTL,
		},
		{
			name:    "STHConsistency-0-7",
			zone:    "good.ct.googleapis.com",
			prefix:  "good",
			paths:   []httpPath{{path: "/good/ct/v1/get-sth-consistency", params: map[string]string{"first": "1234567", "second": "2345678"}}},
			rsps:    []string{jsonSTHConsistency},
			msg:     &dns.Msg{Question: []dns.Question{{Name: "0.1234567.2345678.sth-consistency.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			wantRRs: 1,
			wantTxt: expectByteProof(consist.Consistency, 0, 7),
			wantTTL: respTTL,
		},
		{
			name:    "STHConsistency-8-15",
			zone:    "good.ct.googleapis.com",
			prefix:  "good",
			paths:   []httpPath{{path: "/good/ct/v1/get-sth-consistency", params: map[string]string{"first": "1234567", "second": "2345678"}}},
			rsps:    []string{jsonSTHConsistency},
			msg:     &dns.Msg{Question: []dns.Question{{Name: "8.1234567.2345678.sth-consistency.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			wantRRs: 1,
			wantTxt: expectByteProof(consist.Consistency, 8, 15),
			wantTTL: respTTL,
		},
		{
			name:    "STHConsistency-16-23",
			zone:    "good.ct.googleapis.com",
			prefix:  "good",
			paths:   []httpPath{{path: "/good/ct/v1/get-sth-consistency", params: map[string]string{"first": "1234567", "second": "2345678"}}},
			rsps:    []string{jsonSTHConsistency},
			msg:     &dns.Msg{Question: []dns.Question{{Name: "16.1234567.2345678.sth-consistency.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			wantRRs: 1,
			wantTxt: expectByteProof(consist.Consistency, 16, 23),
			wantTTL: respTTL,
		},
		{
			name:    "STHConsistency-1-8",
			zone:    "good.ct.googleapis.com",
			prefix:  "good",
			paths:   []httpPath{{path: "/good/ct/v1/get-sth-consistency", params: map[string]string{"first": "1234567", "second": "2345678"}}},
			rsps:    []string{jsonSTHConsistency},
			msg:     &dns.Msg{Question: []dns.Question{{Name: "1.1234567.2345678.sth-consistency.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			wantRRs: 1,
			wantTxt: expectByteProof(consist.Consistency, 1, 8),
			wantTTL: respTTL,
		},
		{
			name:    "STHConsistency-9-16",
			zone:    "good.ct.googleapis.com",
			prefix:  "good",
			paths:   []httpPath{{path: "/good/ct/v1/get-sth-consistency", params: map[string]string{"first": "1234567", "second": "2345678"}}},
			rsps:    []string{jsonSTHConsistency},
			msg:     &dns.Msg{Question: []dns.Question{{Name: "9.1234567.2345678.sth-consistency.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			wantRRs: 1,
			wantTxt: expectByteProof(consist.Consistency, 9, 16),
			wantTTL: respTTL,
		},
		{
			name:    "STHConsistency-17-23",
			zone:    "good.ct.googleapis.com",
			prefix:  "good",
			paths:   []httpPath{{path: "/good/ct/v1/get-sth-consistency", params: map[string]string{"first": "1234567", "second": "2345678"}}},
			rsps:    []string{jsonSTHConsistency},
			msg:     &dns.Msg{Question: []dns.Question{{Name: "17.1234567.2345678.sth-consistency.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			wantRRs: 1,
			wantTxt: expectByteProof(consist.Consistency, 17, 23),
			wantTTL: respTTL,
		},
		{
			name:    "STHConsistency-20-23",
			zone:    "good.ct.googleapis.com",
			prefix:  "good",
			paths:   []httpPath{{path: "/good/ct/v1/get-sth-consistency", params: map[string]string{"first": "1234567", "second": "2345678"}}},
			rsps:    []string{jsonSTHConsistency},
			msg:     &dns.Msg{Question: []dns.Question{{Name: "20.1234567.2345678.sth-consistency.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			wantRRs: 1,
			wantTxt: expectByteProof(consist.Consistency, 20, 23),
			wantTTL: respTTL,
		},
		{
			name:      "STHConsistencyBadRange",
			zone:      "good.ct.googleapis.com",
			prefix:    "good",
			paths:     []httpPath{{path: "/good/ct/v1/get-sth-consistency", params: map[string]string{"first": "1234567", "second": "2345678"}}},
			rsps:      []string{jsonSTHConsistency},
			msg:       &dns.Msg{Question: []dns.Question{{Name: "26.1234567.2345678.sth-consistency.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			wantRcode: dns.RcodeServerFailure,
		},
		{
			name:   "Hash",
			zone:   "good.ct.googleapis.com",
			prefix: "good",
			paths: []httpPath{
				{path: "/good/ct/v1/get-sth"},
				{path: "/good/ct/v1/get-proof-by-hash", params: map[string]string{"hash": "D2jUPH4Suig73rU7h8XdRzbvHkLtIHYAU0KQ8D08ZrM=", "tree_size": "1234568"}},
			},
			rsps:    []string{jsonSTH1234568, jsonProofByHash},
			msg:     &dns.Msg{Question: []dns.Question{{Name: "B5UNIPD6CK5CQO66WU5YPRO5I43O6HSC5UQHMACTIKIPAPJ4M2ZQ.hash.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			wantRRs: 1,
			wantTxt: "1234567",
			wantTTL: respTTL,
		},
		{
			name:   "Tree-0-7",
			zone:   "good.ct.googleapis.com",
			prefix: "good",
			paths: []httpPath{
				{path: "/good/ct/v1/get-entry-and-proof", params: map[string]string{"leaf_index": "1234567", "tree_size": "1234568"}},
			},
			rsps:    []string{jsonEntryAndProof},
			msg:     &dns.Msg{Question: []dns.Question{{Name: "0.1234567.1234568.tree.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			wantRRs: 1,
			wantTxt: expectByteProof(proof.AuditPath, 0, 7),
			wantTTL: respTTL,
		},
		{
			name:   "Tree-8-11",
			zone:   "good.ct.googleapis.com",
			prefix: "good",
			paths: []httpPath{
				{path: "/good/ct/v1/get-entry-and-proof", params: map[string]string{"leaf_index": "1234567", "tree_size": "1234568"}},
			},
			rsps:    []string{jsonEntryAndProof},
			msg:     &dns.Msg{Question: []dns.Question{{Name: "8.1234567.1234568.tree.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			wantRRs: 1,
			wantTxt: expectByteProof(proof.AuditPath, 8, 11),
			wantTTL: respTTL,
		},
		{
			name:   "Tree-1-8",
			zone:   "good.ct.googleapis.com",
			prefix: "good",
			paths: []httpPath{
				{path: "/good/ct/v1/get-entry-and-proof", params: map[string]string{"leaf_index": "1234567", "tree_size": "1234568"}},
			},
			rsps:    []string{jsonEntryAndProof},
			msg:     &dns.Msg{Question: []dns.Question{{Name: "1.1234567.1234568.tree.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			wantRRs: 1,
			wantTxt: expectByteProof(proof.AuditPath, 1, 8),
			wantTTL: respTTL,
		},
		{
			name:   "TreeBadRange",
			zone:   "good.ct.googleapis.com",
			prefix: "good",
			paths: []httpPath{
				{path: "/good/ct/v1/get-entry-and-proof", params: map[string]string{"leaf_index": "1234567", "tree_size": "1234568"}},
			},
			rsps:      []string{jsonEntryAndProof},
			msg:       &dns.Msg{Question: []dns.Question{{Name: "12.1234567.1234568.tree.good.ct.googleapis.com", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}},
			wantRcode: dns.RcodeServerFailure,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ts := serveRspsAt(t, test.paths, test.rsps)
			defer ts.Close()

			lc, err := client.New(fmt.Sprintf("%s/%s", ts.URL, test.prefix), http.DefaultClient, jsonclient.Options{})
			if err != nil {
				t.Fatal(err)
			}
			cfg := &configpb.LogConfig{Prefix: test.prefix, DnsZone: test.zone}
			d := New(cfg, ts.URL, lc, time.Second*10)
			frw := fakeResponseWriter{}
			d.ServeDNS(&frw, test.msg)
			if err := checkResponse(frw, test); err != nil {
				t.Error(err)
			}
		})
	}
}

func makeProof(l int) [][]byte {
	hashes := make([][]byte, 0, l)
	for i := 0; i < l; i++ {
		input := []byte(fmt.Sprintf("hash%d", i))
		hash := sha256.Sum256(input)
		hashes = append(hashes, hash[:])
	}
	return hashes
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

func expectByteProof(proof [][]byte, s, l int) string {
	p := make([]byte, 0, maxProofLen)
	for i := s; i < l; i++ {
		p = append(p, proof[i]...)
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

// We should always get a single message written to the response writer.
// It should always be an INET class and TXT type. The Query should have
// been copied from the request. There should be 1 RR response in the
// result, unless we expected an error.
func checkResponse(frw fakeResponseWriter, test dnsTest) error {
	if len(frw.messages) != 1 {
		return fmt.Errorf("got: %d msgs written, want: 1", len(frw.messages))
	}

	if got, want := frw.messages[0].Rcode, test.wantRcode; got != want {
		return fmt.Errorf("got Rcode: %d, want: %d", got, want)
	}

	if got, want := frw.messages[0].Question[0].Name, test.msg.Question[0].Name; got != want {
		return fmt.Errorf("got question: %v, want: %v", got, want)
	}

	if got, want := len(frw.messages[0].Answer), test.wantRRs; got != want {
		return fmt.Errorf("got: %d RRs in response, want: %d", got, want)
	}

	if test.wantRRs != 0 {
		answer := frw.messages[0].Answer[0]
		if got, want := answer.Header().Class, dns.ClassINET; got != uint16(want) {
			return fmt.Errorf("got RR class: %d in response, want: INET(%d)", got, want)
		}
		if got, want := answer.Header().Rrtype, dns.TypeTXT; got != want {
			return fmt.Errorf("got RR type: %d in response, want: TXT(%d)", got, want)
		}
		if got, want := answer.Header().Ttl, test.wantTTL; got != want {
			return fmt.Errorf("got TTL: %d in response, want: %d", got, want)
		}
		if len(test.wantTxt) != 0 {
			rr := answer.(*dns.TXT)
			if len(rr.Txt) != 1 {
				return fmt.Errorf("got %d TXT responses in Answer, want: 1", len(rr.Txt))
			}
			if got, want := rr.Txt[0], test.wantTxt; got != want {
				return fmt.Errorf("got TXT response: %s, want: %s", got, want)
			}
		}
	}

	return nil
}

// serveHandlerAt returns a test HTTP server that only expects requests at the given path, and invokes
// the provided handler for that path.
func serveHandlerAt(t *testing.T, handlers map[string]http.HandlerFunc) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h, ok := handlers[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			t.Fatalf("Incorrect URL path: %s", r.URL.Path)
		}
		h(w, r)
	}))
}

// serveRspAt returns a test HTTP server that returns canned response body rsps for given paths.
// If query parameters are specified then they must be present in the request with the
// correct values.
func serveRspsAt(t *testing.T, paths []httpPath, rsps []string) *httptest.Server {
	t.Helper()
	if len(paths) != len(rsps) {
		t.Fatalf("Mismatched paths (%d) and rsps (%d)", len(paths), len(rsps))
	}

	m := make(map[string]http.HandlerFunc)
	for p := 0; p < len(paths); p++ {
		rsp := rsps[p]
		pp := paths[p]
		m[pp.path] = func(w http.ResponseWriter, r *http.Request) {
			for k, v := range pp.params {
				if strings.ToLower(r.FormValue(k)) != strings.ToLower(v) {
					w.WriteHeader(http.StatusInternalServerError)
					t.Errorf("Incorrect query parameter: %v -> %v: %v", k, v, r.Form.Encode())
					return
				}
			}
			fmt.Fprintf(w, rsp)
		}
	}
	return serveHandlerAt(t, m)
}
