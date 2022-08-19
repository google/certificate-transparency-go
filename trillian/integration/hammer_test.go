// Copyright 2017 Google LLC. All Rights Reserved.
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

package integration

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/trillian/ctfe/configpb"
	"github.com/google/certificate-transparency-go/x509"
	"google.golang.org/protobuf/types/known/timestamppb"

	ct "github.com/google/certificate-transparency-go"
)

func TestHammer_NotAfter(t *testing.T) {
	keys := loadTestKeys(t)

	s, lc := newFakeCTServer(t)
	defer s.close()

	now := time.Now()
	notAfterStart := now.Add(-48 * time.Hour)
	notAfterOverride := now.Add(23 * time.Hour)
	notAfterLimit := now.Add(48 * time.Hour)

	ctx := context.Background()
	addChain := func(hs *hammerState) error { return hs.addChain(ctx) }
	addPreChain := func(hs *hammerState) error { return hs.addPreChain(ctx) }

	tests := []struct {
		desc                                           string
		fn                                             func(hs *hammerState) error
		notAfterOverride, notAfterStart, notAfterLimit time.Time
		// wantNotAfter is only checked if not zeroed
		wantNotAfter time.Time
	}{
		{
			desc: "nonTemporalAddChain",
			fn:   addChain,
		},
		{
			desc: "nonTemporalAddPreChain",
			fn:   addPreChain,
		},
		{
			desc:             "nonTemporalFixedAddChain",
			fn:               addChain,
			notAfterOverride: notAfterOverride,
			wantNotAfter:     notAfterOverride,
		},
		{
			desc:             "nonTemporalFixedAddPreChain",
			fn:               addPreChain,
			notAfterOverride: notAfterOverride,
			wantNotAfter:     notAfterOverride,
		},
		{
			desc:          "temporalAddChain",
			fn:            addChain,
			notAfterStart: notAfterStart,
			notAfterLimit: notAfterLimit,
		},
		{
			desc:          "temporalAddPreChain",
			fn:            addPreChain,
			notAfterStart: notAfterStart,
			notAfterLimit: notAfterLimit,
		},
		{
			desc:             "temporalFixedAddChain",
			fn:               addChain,
			notAfterOverride: notAfterOverride,
			notAfterStart:    notAfterStart,
			notAfterLimit:    notAfterLimit,
			wantNotAfter:     notAfterOverride,
		},
		{
			desc:             "temporalFixedAddPreChain",
			fn:               addPreChain,
			notAfterOverride: notAfterOverride,
			notAfterStart:    notAfterStart,
			notAfterLimit:    notAfterLimit,
			wantNotAfter:     notAfterOverride,
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			s.reset()

			var startPB, limitPB *timestamppb.Timestamp
			if ts := test.notAfterStart; ts.UnixNano() > 0 {
				startPB = timestamppb.New(ts)
			}
			if ts := test.notAfterLimit; ts.UnixNano() > 0 {
				limitPB = timestamppb.New(ts)
			}
			generator, err := NewSyntheticChainGenerator(keys.leafChain, keys.signer, test.notAfterOverride)
			if err != nil {
				t.Fatalf("Failed to build chain generator: %v", err)
			}
			hs, err := newHammerState(&HammerConfig{
				ChainGenerator: generator,
				ClientPool:     RandomPool{lc},
				LogCfg: &configpb.LogConfig{
					NotAfterStart: startPB,
					NotAfterLimit: limitPB,
				},
			})
			if err != nil {
				t.Fatalf("newHammerState() returned err = %v", err)
			}

			if err := test.fn(hs); err != nil {
				t.Fatalf("addChain() returned err = %v", err)
			}
			if got := len(s.addedCerts); got != 1 {
				t.Fatalf("unexpected number of certs (%d) added to server", got)
			}
			got := s.addedCerts[0].NotAfter
			temporal := startPB != nil || limitPB != nil
			fixed := test.wantNotAfter.UnixNano() > 0
			if fixed {
				// Expect a fixed NotAfter in the generated cert.
				delta := got.Sub(test.wantNotAfter)
				if delta < 0 {
					delta = -delta
				}
				if delta > time.Second {
					t.Errorf("cert has NotAfter = %v, want = %v", got, test.wantNotAfter)
				}
			} else {
				// For a temporal log, expect the NotAfter in the generated cert to be in range.
				if temporal && (got.Before(test.notAfterStart) || got.After(test.notAfterLimit)) {
					t.Errorf("cert has NotAfter = %v, want %v <= NotAfter <= %v", got, test.notAfterStart, test.notAfterLimit)
				}
			}
		})
	}
}

// fakeCTServer is a fake HTTP server that mimics a CT frontend.
// It supports add-chain and add-pre-chain methods and saves the first certificate of the chain in
// the addCerts field.
// Callers should call reset() before usage to reset internal state and defer-call close() to ensure
// the server is stopped and resources are freed.
type fakeCTServer struct {
	lis    net.Listener
	server *http.Server

	addedCerts []*x509.Certificate
	sthNow     ct.SignedTreeHead

	getConsistencyCalled bool
}

func (s *fakeCTServer) addChain(w http.ResponseWriter, req *http.Request) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}

	addReq := &ct.AddChainRequest{}
	if err := json.Unmarshal(body, addReq); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}

	cert, err := x509.ParseCertificate(addReq.Chain[0])
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	s.addedCerts = append(s.addedCerts, cert)

	dsBytes, err := tls.Marshal(tls.DigitallySigned{})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	resp := &ct.AddChainResponse{
		SCTVersion: ct.V1,
		Signature:  dsBytes,
	}
	respBytes, err := json.Marshal(resp)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(respBytes)
}

func (s *fakeCTServer) close() {
	if s.server != nil {
		s.server.Close()
	}
	if s.lis != nil {
		s.lis.Close()
	}
}

func (s *fakeCTServer) reset() {
	s.addedCerts = nil
}

func (s *fakeCTServer) serve() {
	s.server.Serve(s.lis)
}

func (s *fakeCTServer) getSTH(w http.ResponseWriter, req *http.Request) {
	resp := &ct.GetSTHResponse{
		TreeSize:       s.sthNow.TreeSize,
		Timestamp:      s.sthNow.Timestamp,
		SHA256RootHash: []byte(s.sthNow.SHA256RootHash[:]),
	}
	var err error
	resp.TreeHeadSignature, err = tls.Marshal(s.sthNow.TreeHeadSignature)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}

	respBytes, err := json.Marshal(resp)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(respBytes)
}

func (s *fakeCTServer) getConsistency(w http.ResponseWriter, req *http.Request) {
	cp := &ct.GetSTHConsistencyResponse{
		Consistency: [][]byte{[]byte("bogus")},
	}
	respBytes, err := json.Marshal(cp)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(respBytes)

	s.getConsistencyCalled = true
}

func writeErr(w http.ResponseWriter, status int, err error) {
	w.WriteHeader(status)
	io.WriteString(w, err.Error())
}

// newFakeCTServer creates and starts a fakeCTServer.
// It returns the started server and a client to the same server.
func newFakeCTServer(t *testing.T) (*fakeCTServer, *client.LogClient) {
	s := &fakeCTServer{}

	var err error
	s.lis, err = net.Listen("tcp", "")
	if err != nil {
		s.close()
		t.Fatalf("net.Listen() returned err = %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/ct/v1/add-chain", s.addChain)
	mux.HandleFunc("/ct/v1/add-pre-chain", s.addChain)
	mux.HandleFunc("/ct/v1/get-sth", s.getSTH)
	mux.HandleFunc("/ct/v1/get-sth-consistency", s.getConsistency)

	s.server = &http.Server{Handler: mux}
	go s.serve()

	lc, err := client.New(fmt.Sprintf("http://%s", s.lis.Addr()), nil, jsonclient.Options{})
	if err != nil {
		t.Fatalf("client.New() returned err = %v", err)
	}

	return s, lc
}

// testKeys contains all keys and associated signer required for hammer tests.
type testKeys struct {
	caChain, leafChain []ct.ASN1Cert
	caCert, leafCert   *x509.Certificate
	signer             crypto.Signer
}

// loadTestKeys loads the test keys from the testdata/ directory.
func loadTestKeys(t *testing.T) *testKeys {
	t.Helper()

	const testdataPath = "../testdata/"

	caChain, err := GetChain(testdataPath, "int-ca.cert")
	if err != nil {
		t.Fatalf("GetChain() returned err = %v", err)
	}
	leafChain, err := GetChain(testdataPath, "leaf01.chain")
	if err != nil {
		t.Fatalf("GetChain() returned err = %v", err)
	}
	caCert, err := x509.ParseCertificate(caChain[0].Data)
	if err != nil {
		t.Fatalf("x509.ParseCertificate() returned err = %v", err)
	}
	leafCert, err := x509.ParseCertificate(leafChain[0].Data)
	if err != nil {
		t.Fatalf("x509.ParseCertificate() returned err = %v", err)
	}
	signer, err := MakeSigner(testdataPath)
	if err != nil {
		t.Fatalf("MakeSigner() returned err = %v", err)
	}

	return &testKeys{
		caChain:   caChain,
		leafChain: leafChain,
		caCert:    caCert,
		leafCert:  leafCert,
		signer:    signer,
	}
}

func TestChooseCertToAdd(t *testing.T) {
	for _, test := range []struct {
		desc    string
		dupeInN int
		wantNew bool
		wantOld bool
	}{
		{
			desc:    "all new",
			dupeInN: 0,
			wantNew: true,
		},
		{
			desc:    "all old",
			dupeInN: 1,
			wantOld: true,
		},
		{
			desc:    "mix",
			dupeInN: 2,
			wantNew: true,
			wantOld: true,
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			state := hammerState{cfg: &HammerConfig{DuplicateChance: test.dupeInN}}
			var gotNew, gotOld bool
			for i := 0; i < 100; i++ {
				switch state.chooseCertToAdd() {
				case NewCert:
					gotNew = true
				case FirstCert, LastCert:
					gotOld = true
				}
			}
			if gotNew && !test.wantNew {
				t.Errorf("got NewCert but expected none")
			}
			if !gotNew && test.wantNew {
				t.Errorf("got no NewCerts but expected some")
			}
			if gotOld && !test.wantOld {
				t.Errorf("got First/Last cert but expected none")
			}
			if !gotOld && test.wantOld {
				t.Errorf("got no First/Last cert but expected some")
			}
		})
	}
}

func TestStrictSTHConsistencySize(t *testing.T) {
	ctx := context.Background()

	for _, test := range []struct {
		name       string
		strict     bool
		sthNowSize uint64
		wantSkip   bool
	}{
		{name: "strict", strict: true, wantSkip: true},
		{name: "relaxed_too_small", sthNowSize: 1, wantSkip: true},
		{name: "relaxed_invent_size", sthNowSize: 10, wantSkip: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, lc := newFakeCTServer(t)
			defer s.close()

			s.sthNow.TreeSize = test.sthNowSize

			hs, err := newHammerState(&HammerConfig{
				StrictSTHConsistencySize: test.strict,
				ClientPool:               RandomPool{lc},
				LogCfg:                   &configpb.LogConfig{},
			})
			if err != nil {
				t.Fatalf("Failed to create HammerState: %v", err)
			}

			err = hs.getSTHConsistency(ctx)
			_, gotSkip := err.(errSkip)
			if gotSkip != test.wantSkip {
				t.Fatalf("got err %v, wanted Skip=%v", err, test.wantSkip)
			}
			if err != nil && !gotSkip {
				t.Fatalf("got unexpected err %v", err)
			}
			if test.wantSkip {
				return
			}

			if !s.getConsistencyCalled {
				t.Fatal("hammer failed to request a consistency proof for invented tree size")
			}
		})
	}
}
