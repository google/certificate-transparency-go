// Copyright 2019 Google Inc. All Rights Reserved.
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
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/loglist2"
	"github.com/google/certificate-transparency-go/testdata"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/trillian/monitoring"
)

// stubLogListRefresher produces error on each Refresh call.
type stubLogListRefresher struct {
}

func (llr stubLogListRefresher) Refresh() (*LogListData, error) {
	return nil, fmt.Errorf("stub Log List Refresher produces no Log List")
}
func (llr stubLogListRefresher) LastJSON() []byte {
	return nil
}
func (llr stubLogListRefresher) Source() string {
	return "stub"
}

func stubLogListManager() *LogListManager {
	return NewLogListManager(stubLogListRefresher{})
}

var imf monitoring.InertMetricFactory

func TestProxyRefreshLLErr(t *testing.T) {
	p := NewProxy(stubLogListManager(), GetDistributorBuilder(ChromeCTPolicy, NewStubLogClient, imf), imf)

	_, err := p.llWatcher.RefreshLogList(context.Background())
	if err == nil {
		t.Errorf("p.RefreshLogList() on stubLogListRefresher expected to get error, got none")
	}
}

func TestProxyBrokenDistributor(t *testing.T) {
	p := NewProxy(stubLogListManager(), GetDistributorBuilder(ChromeCTPolicy, newNoLogClient, imf), imf)

	_, err := p.llWatcher.RefreshLogList(context.Background())
	if err == nil {
		t.Errorf("p.RefreshLogList() on brokenDistributorFactory expected to get error, got none")
	}
}

// Stub for AddLogCLient interface
type stubNoRootsLogClient struct {
	logURL string
}

func (m stubNoRootsLogClient) AddChain(ctx context.Context, chain []ct.ASN1Cert) (*ct.SignedCertificateTimestamp, error) {
	return nil, fmt.Errorf("log %q has no roots", m.logURL)
}

func (m stubNoRootsLogClient) AddPreChain(ctx context.Context, chain []ct.ASN1Cert) (*ct.SignedCertificateTimestamp, error) {
	return nil, fmt.Errorf("log %q has no roots", m.logURL)
}

func (m stubNoRootsLogClient) GetAcceptedRoots(ctx context.Context) ([]ct.ASN1Cert, error) {
	//fmt.Printf("No roots get accepted roots")
	return nil, fmt.Errorf("stubNoRootsLogClient cannot provide roots")
}

func buildStubNoRootsLogClient(log *loglist2.Log) (client.AddLogClient, error) {
	return stubNoRootsLogClient{logURL: log.URL}, nil
}

func TestProxyRefreshRootsErr(t *testing.T) {
	f, err := createTempFile(testdata.SampleLogList2)
	if err != nil {
		t.Fatalf("createTempFile(%q) = (_, %q), want (_, nil)", testdata.SampleLogList2, err)
	}
	defer os.Remove(f)

	llr := NewLogListRefresher(f)
	p := NewProxy(NewLogListManager(llr), GetDistributorBuilder(ChromeCTPolicy, buildStubNoRootsLogClient, imf), imf)
	p.Run(context.Background(), time.Hour, time.Hour)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// number of active Logs within sampleLogList
	var numLogs = 2
	for i := 0; i < numLogs; i++ {
		select {
		case <-ctx.Done():
			t.Errorf("p.RefreshLogList() on noRootsDistributorFactory expected to emit error for each Log, got %d", i)
			return
		case <-p.Errors:
		}
	}
}

func TestProxyInitState(t *testing.T) {
	f, err := createTempFile(testdata.SampleLogList)
	if err != nil {
		t.Fatalf("createTempFile(%q) = (_, %q), want (_, nil)", testdata.SampleLogList, err)
	}
	defer os.Remove(f)

	llr := NewLogListRefresher(f)
	p := NewProxy(NewLogListManager(llr), GetDistributorBuilder(ChromeCTPolicy, buildStubNoRootsLogClient, imf), imf)
	p.Run(context.Background(), time.Millisecond, time.Hour)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

Init:
	for {
		select {
		case <-ctx.Done():
			t.Fatalf("p.Run() expected to send init signal, got none")
		case b, ok := <-p.Init:
			if !ok {
				t.Fatalf("p.Run() expected to send 'true' init signal via Init channel, but channel is closed")
			}
			if b != true {
				t.Fatalf("p.Run() expected to send 'true' init signal, got false")
			}
			break Init
		case e := <-p.Errors:
			t.Log(e)
		}
	}

	sampleLogListUpdate := strings.Replace(testdata.SampleLogList, "ct.googleapis.com/racketeer/", "ct.googleapis.com/racketeer/v2/", 1)
	if err := ioutil.WriteFile(f, []byte(sampleLogListUpdate), 0644); err != nil {
		t.Fatalf("unable to update Log-list data file: %q", err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-p.Init:
			if ok {
				t.Fatalf("p.Refresh() after initial p.Run() sent signal into Init-channel, expected none")
			}
		case <-p.Errors:
		}
	}
}

func TestASN1MarshalSCT(t *testing.T) {
	want, _ := hex.DecodeString("047a0078007600df1c2ec11500945247a96168325ddc5c7959e8f7c6d388fc002e0bbd3f74d7640000013ddb27ded900000403004730450220606e10ae5c2d5a1b0aed49dc4937f48de71a4e9784e9c208dfbfe9ef536cf7f2022100beb29c72d7d06d61d06bdb38a069469aa86fe12e18bb7cc45689a2c0187ef5a5")
	rawSCT := testdata.TestCertProof
	var sct ct.SignedCertificateTimestamp
	_, err := tls.Unmarshal(rawSCT, &sct)
	if err != nil {
		t.Fatalf("failed to tls-unmarshal test certificate proof: %s", err)
	}
	assignedSCT := AssignedSCT{LogURL: "ct.googleapis.com/racketeer/", SCT: &sct}
	assignedSCTs := []*AssignedSCT{&assignedSCT}
	got, err := ASN1MarshalSCTs(assignedSCTs)
	if err != nil {
		t.Fatalf("ASN1MarshalSCT() returned error %v", err)
	}
	if !(bytes.Equal(got, want)) {
		t.Fatalf("ASN1MarshalSCT() returned unexpected output: \n got: %x\nwant: %x", got, want)
	}
}
