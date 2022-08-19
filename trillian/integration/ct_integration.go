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

// Package integration holds test-only code for running tests on
// an integrated system of the CT personality and a Trillian log.
package integration

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/trillian/ctfe"
	"github.com/google/certificate-transparency-go/trillian/ctfe/configpb"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509/pkix"
	"github.com/google/trillian"
	"github.com/google/trillian/crypto/keyspb"
	"github.com/kylelemons/godebug/pretty"
	"github.com/transparency-dev/merkle"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"golang.org/x/net/context/ctxhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	ct "github.com/google/certificate-transparency-go"
)

const (
	reqStatsRE = `^http_reqs{ep="(\w+)",logid="(\d+)"} ([.\d]+)$`
	rspStatsRE = `^http_rsps{ep="(\w+)",logid="(\d+)",rc="(\d+)"} (?P<val>[.\d]+)$`
)

// DefaultTransport is a http Transport more suited for use in the hammer
// context.
// In particular it increases the number of reusable connections to the same
// host. This helps to prevent starvation of ports through TIME_WAIT when
// using the hammer with a high number of parallel chain submissions.
var DefaultTransport = &http.Transport{
	Proxy: http.ProxyFromEnvironment,
	DialContext: (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext,
	MaxIdleConns:          1000,
	MaxIdleConnsPerHost:   1000,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
}

// ClientPool describes an entity which produces LogClient instances.
type ClientPool interface {
	// Next returns the next LogClient instance to be used.
	Next() *client.LogClient
}

// RandomPool holds a collection of CT LogClient instances.
type RandomPool []*client.LogClient

var _ ClientPool = &RandomPool{}

// Next picks a random client from the pool.
func (p RandomPool) Next() *client.LogClient {
	if len(p) == 0 {
		return nil
	}
	return p[rand.Intn(len(p))]
}

// NewRandomPool creates a pool which returns a random client from list of servers.
func NewRandomPool(servers string, pubKey *keyspb.PublicKey, prefix string) (ClientPool, error) {
	opts := jsonclient.Options{
		PublicKeyDER: pubKey.GetDer(),
		UserAgent:    "ct-go-integrationtest/1.0",
	}

	hc := &http.Client{Transport: DefaultTransport}

	var pool RandomPool
	for _, s := range strings.Split(servers, ",") {
		c, err := client.New(fmt.Sprintf("http://%s/%s", s, prefix), hc, opts)
		if err != nil {
			return nil, fmt.Errorf("failed to create LogClient instance: %v", err)
		}
		pool = append(pool, c)
	}
	return &pool, nil
}

// testInfo holds per-test information.
type testInfo struct {
	prefix         string
	cfg            *configpb.LogConfig
	metricsServers string
	adminServer    string
	stats          *logStats
	pool           ClientPool
	hasher         merkle.LogHasher
}

func (t *testInfo) checkStats() error {
	return t.stats.check(t.cfg, t.metricsServers)
}

func (t *testInfo) client() *client.LogClient {
	return t.pool.Next()
}

// awaitTreeSize loops until the an STH is retrieved that is the specified size (or larger, if exact is false).
func (t *testInfo) awaitTreeSize(ctx context.Context, size uint64, exact bool, mmd time.Duration) (*ct.SignedTreeHead, error) {
	var sth *ct.SignedTreeHead
	deadline := time.Now().Add(mmd)
	for sth == nil || sth.TreeSize < size {
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("deadline for STH inclusion expired (MMD=%v)", mmd)
		}
		time.Sleep(200 * time.Millisecond)
		var err error
		sth, err = t.client().GetSTH(ctx)
		if t.stats != nil {
			t.stats.expect(ctfe.GetSTHName, 200)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to get STH: %v", err)
		}
	}
	if exact && sth.TreeSize != size {
		return nil, fmt.Errorf("sth.TreeSize=%d; want: %d", sth.TreeSize, size)
	}
	return sth, nil
}

// checkInclusionOf checks that a given certificate chain and associated SCT are included
// under a signed tree head.
func (t *testInfo) checkInclusionOf(ctx context.Context, chain []ct.ASN1Cert, sct *ct.SignedCertificateTimestamp, sth *ct.SignedTreeHead) error {
	leaf := ct.MerkleTreeLeaf{
		Version:  ct.V1,
		LeafType: ct.TimestampedEntryLeafType,
		TimestampedEntry: &ct.TimestampedEntry{
			Timestamp:  sct.Timestamp,
			EntryType:  ct.X509LogEntryType,
			X509Entry:  &(chain[0]),
			Extensions: sct.Extensions,
		},
	}
	leafHash, err := ct.LeafHashForLeaf(&leaf)
	if err != nil {
		return fmt.Errorf("ct.LeafHashForLeaf(leaf[%d])=(nil,%v); want (_,nil)", 0, err)
	}
	rsp, err := t.client().GetProofByHash(ctx, leafHash[:], sth.TreeSize)
	t.stats.expect(ctfe.GetProofByHashName, 200)
	if err != nil {
		return fmt.Errorf("got GetProofByHash(sct[%d],size=%d)=(nil,%v); want (_,nil)", 0, sth.TreeSize, err)
	}
	if err := proof.VerifyInclusion(t.hasher, uint64(rsp.LeafIndex), sth.TreeSize, leafHash[:], rsp.AuditPath, sth.SHA256RootHash[:]); err != nil {
		return fmt.Errorf("got VerifyInclusion(%d, %d,...)=%v", 0, sth.TreeSize, err)
	}
	return nil
}

// checkInclusionOfPreCert checks a pre-cert is included at given index.
func (t *testInfo) checkInclusionOfPreCert(ctx context.Context, tbs []byte, issuer *x509.Certificate, sct *ct.SignedCertificateTimestamp, sth *ct.SignedTreeHead) error {
	leaf := ct.MerkleTreeLeaf{
		Version:  ct.V1,
		LeafType: ct.TimestampedEntryLeafType,
		TimestampedEntry: &ct.TimestampedEntry{
			Timestamp: sct.Timestamp,
			EntryType: ct.PrecertLogEntryType,
			PrecertEntry: &ct.PreCert{
				IssuerKeyHash:  sha256.Sum256(issuer.RawSubjectPublicKeyInfo),
				TBSCertificate: tbs,
			},
			Extensions: sct.Extensions,
		},
	}
	leafHash, err := ct.LeafHashForLeaf(&leaf)
	if err != nil {
		return fmt.Errorf("ct.LeafHashForLeaf(precertLeaf)=(nil,%v); want (_,nil)", err)
	}
	rsp, err := t.client().GetProofByHash(ctx, leafHash[:], sth.TreeSize)
	t.stats.expect(ctfe.GetProofByHashName, 200)
	if err != nil {
		return fmt.Errorf("got GetProofByHash(sct, size=%d)=nil,%v", sth.TreeSize, err)
	}
	fmt.Printf("%s: Inclusion proof leaf %d @ %d -> root %d = %x\n", t.prefix, rsp.LeafIndex, sct.Timestamp, sth.TreeSize, rsp.AuditPath)
	if err := proof.VerifyInclusion(t.hasher, uint64(rsp.LeafIndex), sth.TreeSize, leafHash[:], rsp.AuditPath, sth.SHA256RootHash[:]); err != nil {
		return fmt.Errorf("got VerifyInclusion(%d,%d,...)=%v; want nil", rsp.LeafIndex, sth.TreeSize, err)
	}
	if err := t.checkStats(); err != nil {
		return fmt.Errorf("stats check failed: %v", err)
	}
	return nil
}

// checkPreCertEntry retrieves a pre-cert from a known index and checks it.
func (t *testInfo) checkPreCertEntry(ctx context.Context, precertIndex int64, tbs []byte) error {
	precertEntries, err := t.client().GetEntries(ctx, precertIndex, precertIndex)
	t.stats.expect(ctfe.GetEntriesName, 200)
	if err != nil {
		return fmt.Errorf("got GetEntries(%d,%d)=(nil,%v); want (_,nil)", precertIndex, precertIndex, err)
	}
	if len(precertEntries) != 1 {
		return fmt.Errorf("len(entries)=%d; want %d", len(precertEntries), 1)
	}
	leaf := precertEntries[0].Leaf
	ts := leaf.TimestampedEntry
	fmt.Printf("%s: Entry[%d] = {Index:%d Leaf:{Version:%v TS:{EntryType:%v Timestamp:%v}}}\n",
		t.prefix, precertIndex, precertEntries[0].Index, leaf.Version, ts.EntryType, timeFromMS(ts.Timestamp))

	if ts.EntryType != ct.PrecertLogEntryType {
		return fmt.Errorf("leaf[%d].ts.EntryType=%v; want PrecertLogEntryType", precertIndex, ts.EntryType)
	}
	if !bytes.Equal(ts.PrecertEntry.TBSCertificate, tbs) {
		return fmt.Errorf("leaf[%d].ts.PrecertEntry differs from originally uploaded cert", precertIndex)
	}
	if err := t.checkStats(); err != nil {
		return fmt.Errorf("stats check failed: %v", err)
	}
	return nil
}

// RunCTIntegrationForLog tests against the log with configuration cfg, with a set
// of comma-separated server addresses given by servers, assuming that testdir holds
// a variety of test data files.
// nolint: gocyclo
func RunCTIntegrationForLog(cfg *configpb.LogConfig, servers, metricsServers, testdir string, mmd time.Duration, stats *logStats) error {
	ctx := context.Background()
	pool, err := NewRandomPool(servers, cfg.PublicKey, cfg.Prefix)
	if err != nil {
		return fmt.Errorf("failed to create pool: %v", err)
	}
	t := testInfo{
		prefix:         cfg.Prefix,
		cfg:            cfg,
		metricsServers: metricsServers,
		stats:          stats,
		pool:           pool,
		hasher:         rfc6962.DefaultHasher,
	}

	if err := t.checkStats(); err != nil {
		return fmt.Errorf("stats check failed: %v", err)
	}

	// Stage 0: get accepted roots, which should just be the fake CA.
	roots, err := t.client().GetAcceptedRoots(ctx)
	t.stats.expect(ctfe.GetRootsName, 200)
	if err != nil {
		return fmt.Errorf("got GetAcceptedRoots()=(nil,%v); want (_,nil)", err)
	}
	if len(roots) > 2 {
		return fmt.Errorf("len(GetAcceptedRoots())=%d; want <=2", len(roots))
	}

	// Stage 1: get the STH, which should be empty.
	sth0, err := t.client().GetSTH(ctx)
	t.stats.expect(ctfe.GetSTHName, 200)
	if err != nil {
		return fmt.Errorf("got GetSTH()=(nil,%v); want (_,nil)", err)
	}
	if sth0.Version != 0 {
		return fmt.Errorf("sth.Version=%v; want V1(0)", sth0.Version)
	}
	if sth0.TreeSize != 0 {
		return fmt.Errorf("sth.TreeSize=%d; want 0", sth0.TreeSize)
	}
	fmt.Printf("%s: Got STH(time=%q, size=%d): roothash=%x\n", t.prefix, timeFromMS(sth0.Timestamp), sth0.TreeSize, sth0.SHA256RootHash)

	// Stage 2: add a single cert (the intermediate CA), get an SCT.
	var scts [21]*ct.SignedCertificateTimestamp // 0=int-ca, 1-20=leaves
	var chain [21][]ct.ASN1Cert
	chain[0], err = GetChain(testdir, "int-ca.cert")
	if err != nil {
		return fmt.Errorf("failed to load certificate: %v", err)
	}
	issuer, err := x509.ParseCertificate(chain[0][0].Data)
	if err != nil {
		return fmt.Errorf("failed to parse int-ca.cert: %v", err)
	}
	scts[0], err = t.client().AddChain(ctx, chain[0])
	t.stats.expect(ctfe.AddChainName, 200)
	if err != nil {
		return fmt.Errorf("got AddChain(int-ca.cert)=(nil,%v); want (_,nil)", err)
	}
	// Display the SCT
	fmt.Printf("%s: Uploaded int-ca.cert to %v log, got SCT(time=%q)\n", t.prefix, scts[0].SCTVersion, timeFromMS(scts[0].Timestamp))

	// Keep getting the STH until tree size becomes 1 and check the cert is included.
	sth1, err := t.awaitTreeSize(ctx, 1, true, mmd)
	if err != nil {
		return fmt.Errorf("AwaitTreeSize(1)=(nil,%v); want (_,nil)", err)
	}
	fmt.Printf("%s: Got STH(time=%q, size=%d): roothash=%x\n", t.prefix, timeFromMS(sth1.Timestamp), sth1.TreeSize, sth1.SHA256RootHash)
	if err := t.checkStats(); err != nil {
		return fmt.Errorf("stats check failed: %v", err)
	}
	if err := t.checkInclusionOf(ctx, chain[0], scts[0], sth1); err != nil {
		return err
	}

	// Stage 2.5: add the same cert, expect an SCT with the same timestamp as before.
	var sctCopy *ct.SignedCertificateTimestamp
	sctCopy, err = t.client().AddChain(ctx, chain[0])
	if err != nil {
		return fmt.Errorf("got re-AddChain(int-ca.cert)=(nil,%v); want (_,nil)", err)
	}
	t.stats.expect(ctfe.AddChainName, 200)
	if scts[0].Timestamp != sctCopy.Timestamp {
		return fmt.Errorf("got sct @ %v; want @ %v", sctCopy, scts[0])
	}

	// Stage 3: add a second cert, wait for tree size = 2
	chain[1], err = GetChain(testdir, "leaf01.chain")
	if err != nil {
		return fmt.Errorf("failed to load certificate: %v", err)
	}
	scts[1], err = t.client().AddChain(ctx, chain[1])
	t.stats.expect(ctfe.AddChainName, 200)
	if err != nil {
		return fmt.Errorf("got AddChain(leaf01)=(nil,%v); want (_,nil)", err)
	}
	fmt.Printf("%s: Uploaded cert01.chain to %v log, got SCT(time=%q)\n", t.prefix, scts[1].SCTVersion, timeFromMS(scts[1].Timestamp))
	sth2, err := t.awaitTreeSize(ctx, 2, true, mmd)
	if err != nil {
		return fmt.Errorf("failed to get STH for size=1: %v", err)
	}
	fmt.Printf("%s: Got STH(time=%q, size=%d): roothash=%x\n", t.prefix, timeFromMS(sth2.Timestamp), sth2.TreeSize, sth2.SHA256RootHash)

	// Stage 4: get a consistency proof from size 1-> size 2.
	proof12, err := t.client().GetSTHConsistency(ctx, 1, 2)
	t.stats.expect(ctfe.GetSTHConsistencyName, 200)
	if err != nil {
		return fmt.Errorf("got GetSTHConsistency(1, 2)=(nil,%v); want (_,nil)", err)
	}
	//                 sth2
	//                 / \
	//  sth1   =>      a b
	//    |            | |
	//   d0           d0 d1
	// So consistency proof is [b] and we should have:
	//   sth2 == SHA256(0x01 | sth1 | b)
	if len(proof12) != 1 {
		return fmt.Errorf("len(proof12)=%d; want 1", len(proof12))
	}
	if err := t.checkCTConsistencyProof(sth1, sth2, proof12); err != nil {
		return fmt.Errorf("got CheckCTConsistencyProof(sth1,sth2,proof12)=%v; want nil", err)
	}
	if err := t.checkStats(); err != nil {
		return fmt.Errorf("stats check failed: %v", err)
	}

	// Stage 4.5: get a consistency proof from size 0-> size 2, which should be empty.
	proof02, err := t.client().GetSTHConsistency(ctx, 0, 2)
	t.stats.expect(ctfe.GetSTHConsistencyName, 200)
	if err != nil {
		return fmt.Errorf("got GetSTHConsistency(0, 2)=(nil,%v); want (_,nil)", err)
	}
	if len(proof02) != 0 {
		return fmt.Errorf("len(proof02)=%d; want 0", len(proof02))
	}
	if err := t.checkStats(); err != nil {
		return fmt.Errorf("stats check failed: %v", err)
	}

	// Stage 5: add certificates 2, 3, 4, 5,...N, for some random N in [4,20]
	atLeast := 4
	count := atLeast + rand.Intn(20-atLeast)
	for i := 2; i <= count; i++ {
		filename := fmt.Sprintf("leaf%02d.chain", i)
		chain[i], err = GetChain(testdir, filename)
		if err != nil {
			return fmt.Errorf("failed to load certificate: %v", err)
		}
		scts[i], err = t.client().AddChain(ctx, chain[i])
		t.stats.expect(ctfe.AddChainName, 200)
		if err != nil {
			return fmt.Errorf("got AddChain(leaf%02d)=(nil,%v); want (_,nil)", i, err)
		}
	}
	fmt.Printf("%s: Uploaded leaf02-leaf%02d to log, got SCTs\n", t.prefix, count)
	if err := t.checkStats(); err != nil {
		return fmt.Errorf("stats check failed: %v", err)
	}

	// Stage 6: keep getting the STH until tree size becomes 1 + N (allows for int-ca.cert).
	treeSize := 1 + count
	sthN, err := t.awaitTreeSize(ctx, uint64(treeSize), true, mmd)
	if err != nil {
		return fmt.Errorf("AwaitTreeSize(%d)=(nil,%v); want (_,nil)", treeSize, err)
	}
	fmt.Printf("%s: Got STH(time=%q, size=%d): roothash=%x\n", t.prefix, timeFromMS(sthN.Timestamp), sthN.TreeSize, sthN.SHA256RootHash)

	// Stage 7: get a consistency proof from 2->(1+N).
	proof2N, err := t.client().GetSTHConsistency(ctx, 2, uint64(treeSize))
	t.stats.expect(ctfe.GetSTHConsistencyName, 200)
	if err != nil {
		return fmt.Errorf("got GetSTHConsistency(2, %d)=(nil,%v); want (_,nil)", treeSize, err)
	}
	fmt.Printf("%s: Proof size 2->%d: %x\n", t.prefix, treeSize, proof2N)
	if err := t.checkCTConsistencyProof(sth2, sthN, proof2N); err != nil {
		return fmt.Errorf("got CheckCTConsistencyProof(sth2,sthN,proof2N)=%v; want nil", err)
	}

	// Stage 8: get entries [1, N] (start at 1 to skip int-ca.cert)
	entries, err := t.client().GetEntries(ctx, 1, int64(count))
	t.stats.expect(ctfe.GetEntriesName, 200)
	if err != nil {
		return fmt.Errorf("got GetEntries(1,%d)=(nil,%v); want (_,nil)", count, err)
	}
	if len(entries) < count {
		return fmt.Errorf("len(entries)=%d; want %d", len(entries), count)
	}
	gotHashes := make(map[[sha256.Size]byte]bool)
	wantHashes := make(map[[sha256.Size]byte]bool)
	for i, entry := range entries {
		leaf := entry.Leaf
		ts := leaf.TimestampedEntry
		if leaf.Version != 0 {
			return fmt.Errorf("leaf[%d].Version=%v; want V1(0)", i, leaf.Version)
		}
		if leaf.LeafType != ct.TimestampedEntryLeafType {
			return fmt.Errorf("leaf[%d].Version=%v; want TimestampedEntryLeafType", i, leaf.LeafType)
		}

		if ts.EntryType != ct.X509LogEntryType {
			return fmt.Errorf("leaf[%d].ts.EntryType=%v; want X509LogEntryType", i, ts.EntryType)
		}
		// The certificates might not be sequenced in the order they were uploaded, so
		// compare the set of hashes.
		gotHashes[sha256.Sum256(ts.X509Entry.Data)] = true
		wantHashes[sha256.Sum256(chain[i+1][0].Data)] = true
	}
	if diff := pretty.Compare(gotHashes, wantHashes); diff != "" {
		return fmt.Errorf("retrieved cert hashes don't match uploaded cert hashes, diff:\n%v", diff)
	}
	fmt.Printf("%s: Got entries [1:%d+1]\n", t.prefix, count)
	if err := t.checkStats(); err != nil {
		return fmt.Errorf("stats check failed: %v", err)
	}

	// Stage 9: get an audit proof for each certificate we have an SCT for.
	for i := 1; i <= count; i++ {
		if err := t.checkInclusionOf(ctx, chain[i], scts[i], sthN); err != nil {
			return err
		}
	}
	fmt.Printf("%s: Got inclusion proofs [1:%d+1]\n", t.prefix, count)
	if err := t.checkStats(); err != nil {
		return fmt.Errorf("stats check failed: %v", err)
	}

	// Stage 10: attempt to upload a corrupt certificate.
	corruptChain := make([]ct.ASN1Cert, len(chain[1]))
	copy(corruptChain, chain[1])
	corruptAt := len(corruptChain[0].Data) - 3
	corruptChain[0].Data[corruptAt] = corruptChain[0].Data[corruptAt] + 1
	if sct, err := t.client().AddChain(ctx, corruptChain); err == nil {
		return fmt.Errorf("got AddChain(corrupt-cert)=(%+v,nil); want (nil,error)", sct)
	}
	t.stats.expect(ctfe.AddChainName, 400)
	fmt.Printf("%s: AddChain(corrupt-cert)=nil,%v\n", t.prefix, err)

	// Stage 11: attempt to upload a certificate without chain.
	if sct, err := t.client().AddChain(ctx, chain[1][0:0]); err == nil {
		return fmt.Errorf("got AddChain(leaf-only)=(%+v,nil); want (nil,error)", sct)
	}
	t.stats.expect(ctfe.AddChainName, 400)
	fmt.Printf("%s: AddChain(leaf-only)=nil,%v\n", t.prefix, err)
	if err := t.checkStats(); err != nil {
		return fmt.Errorf("stats check failed: %v", err)
	}

	// Stage 12: build and add a pre-certificate.
	signer, err := MakeSigner(testdir)
	if err != nil {
		return fmt.Errorf("failed to retrieve signer for re-signing: %v", err)
	}
	generator, err := NewSyntheticChainGenerator(chain[1], signer, time.Time{})
	if err != nil {
		return fmt.Errorf("failed to create chain generator: %v", err)
	}

	prechain, tbs, err := generator.PreCertChain()
	if err != nil {
		return fmt.Errorf("failed to build pre-certificate: %v", err)
	}
	precertSCT, err := t.client().AddPreChain(ctx, prechain)
	t.stats.expect(ctfe.AddPreChainName, 200)
	if err != nil {
		return fmt.Errorf("got AddPreChain()=(nil,%v); want (_,nil)", err)
	}
	fmt.Printf("%s: Uploaded precert to %v log, got SCT(time=%q)\n", t.prefix, precertSCT.SCTVersion, timeFromMS(precertSCT.Timestamp))
	treeSize++
	sthN1, err := t.awaitTreeSize(ctx, uint64(treeSize), true, mmd)
	if err != nil {
		return fmt.Errorf("AwaitTreeSize(%d)=(nil,%v); want (_,nil)", treeSize, err)
	}
	fmt.Printf("%s: Got STH(time=%q, size=%d): roothash=%x\n", t.prefix, timeFromMS(sthN1.Timestamp), sthN1.TreeSize, sthN1.SHA256RootHash)

	// Stage 13: retrieve and check pre-cert.
	precertIndex := int64(count + 1)
	if err := t.checkPreCertEntry(ctx, precertIndex, tbs); err != nil {
		return fmt.Errorf("failed to check pre-cert entry: %v", err)
	}

	// Stage 14: get an inclusion proof for the precert.
	if err := t.checkInclusionOfPreCert(ctx, tbs, issuer, precertSCT, sthN1); err != nil {
		return fmt.Errorf("failed to check inclusion of pre-cert entry: %v", err)
	}

	// Stage 15: invalid consistency proof
	if rsp, err := t.client().GetSTHConsistency(ctx, 2, 299); err == nil {
		return fmt.Errorf("got GetSTHConsistency(2,299)=(%+v,nil); want (nil,_)", rsp)
	}
	t.stats.expect(ctfe.GetSTHConsistencyName, 400)
	fmt.Printf("%s: GetSTHConsistency(2,299)=(nil,_)\n", t.prefix)

	// Stage 16: invalid inclusion proof; expect a client.RspError{404}.
	wrong := sha256.Sum256([]byte("simply wrong"))
	if rsp, err := t.client().GetProofByHash(ctx, wrong[:], sthN1.TreeSize); err == nil {
		return fmt.Errorf("got GetProofByHash(wrong, size=%d)=(%v,nil); want (nil,_)", sthN1.TreeSize, rsp)
	} else if rspErr, ok := err.(client.RspError); ok {
		if rspErr.StatusCode != http.StatusNotFound {
			return fmt.Errorf("got GetProofByHash(wrong)=_, %d; want (nil, 404)", rspErr.StatusCode)
		}
	} else {
		return fmt.Errorf("got GetProofByHash(wrong)=%+v (%T); want (client.RspError)", err, err)
	}
	t.stats.expect(ctfe.GetProofByHashName, 404)
	fmt.Printf("%s: GetProofByHash(wrong,%d)=(nil,_)\n", t.prefix, sthN1.TreeSize)

	// Stage 17: build and add a pre-certificate signed by a pre-issuer.
	preIssuerChain, preTBS, err := makePreIssuerPrecertChain(chain[1], issuer, signer)
	if err != nil {
		return fmt.Errorf("failed to build pre-issued pre-certificate: %v", err)
	}
	preIssuerCertSCT, err := pool.Next().AddPreChain(ctx, preIssuerChain)
	stats.expect(ctfe.AddPreChainName, 200)
	if err != nil {
		return fmt.Errorf("got AddPreChain()=(nil,%v); want (_,nil)", err)
	}
	fmt.Printf("%s: Uploaded pre-issued precert to %v log, got SCT(time=%q)\n", t.prefix, precertSCT.SCTVersion, timeFromMS(precertSCT.Timestamp))
	treeSize++
	sthN2, err := t.awaitTreeSize(ctx, uint64(treeSize), true, mmd)
	if err != nil {
		return fmt.Errorf("AwaitTreeSize(%d)=(nil,%v); want (_,nil)", treeSize, err)
	}
	fmt.Printf("%s: Got STH(time=%q, size=%d): roothash=%x\n", t.prefix, timeFromMS(sthN2.Timestamp), sthN2.TreeSize, sthN2.SHA256RootHash)

	// Stage 18: retrieve and check pre-issued pre-cert.
	preIssuerCertIndex := int64(count + 2)
	if err := t.checkPreCertEntry(ctx, preIssuerCertIndex, preTBS); err != nil {
		return fmt.Errorf("failed to check pre-issued pre-cert entry: %v", err)
	}

	// Stage 19: get an inclusion proof for the pre-issued precert.
	if err := t.checkInclusionOfPreCert(ctx, preTBS, issuer, preIssuerCertSCT, sthN2); err != nil {
		return fmt.Errorf("failed to check inclusion of pre-cert entry: %v", err)
	}

	// Final stats check.
	if err := t.checkStats(); err != nil {
		return fmt.Errorf("stats check failed: %v", err)
	}
	return nil
}

// RunCTLifecycleForLog does a simple log lifecycle test. The log
// is assumed to be newly created when this test runs. A random number of
// entries are then submitted to build up a queue. The log is set to
// DRAINING state and the test checks that all the entries are integrated
// into the tree and we can verify a consistency proof to the latest entry.
func RunCTLifecycleForLog(cfg *configpb.LogConfig, servers, metricsServers, adminServer string, testDir string, mmd time.Duration, stats *logStats) error {
	// Retrieve the test data.
	caChain, err := GetChain(testDir, "int-ca.cert")
	if err != nil {
		return err
	}
	leafChain, err := GetChain(testDir, "leaf01.chain")
	if err != nil {
		return err
	}
	signer, err := MakeSigner(testDir)
	if err != nil {
		return err
	}
	generator, err := NewSyntheticChainGenerator(leafChain, signer, time.Time{})
	if err != nil {
		return err
	}

	ctx := context.Background()
	pool, err := NewRandomPool(servers, cfg.PublicKey, cfg.Prefix)
	if err != nil {
		return fmt.Errorf("failed to create pool: %v", err)
	}
	t := testInfo{
		prefix:         cfg.Prefix,
		cfg:            cfg,
		metricsServers: metricsServers,
		adminServer:    adminServer,
		stats:          stats,
		pool:           pool,
		hasher:         rfc6962.DefaultHasher,
	}

	if err := t.checkStats(); err != nil {
		return fmt.Errorf("stats check failed: %v", err)
	}

	// Stage 0: get accepted roots, which should just be the fake CA.
	roots, err := t.client().GetAcceptedRoots(ctx)
	t.stats.expect(ctfe.GetRootsName, 200)
	if err != nil {
		return fmt.Errorf("got GetAcceptedRoots()=(nil,%v); want (_,nil)", err)
	}
	if got := len(roots); got != 1 {
		return fmt.Errorf("len(GetAcceptedRoots())=%d; want 1", got)
	}

	// Stage 1: get the STH, which should be empty.
	sth0, err := t.client().GetSTH(ctx)
	t.stats.expect(ctfe.GetSTHName, 200)
	if err != nil {
		return fmt.Errorf("got GetSTH()=(nil,%v); want (_,nil)", err)
	}
	if sth0.Version != 0 {
		return fmt.Errorf("sth.Version=%v; want V1(0)", sth0.Version)
	}
	if sth0.TreeSize != 0 {
		return fmt.Errorf("sth.TreeSize=%d; want 0", sth0.TreeSize)
	}
	fmt.Printf("%s: Got STH(time=%q, size=%d): roothash=%x\n", t.prefix, timeFromMS(sth0.Timestamp), sth0.TreeSize, sth0.SHA256RootHash)

	// Stage 2: add certificates 2, 3, 4, 5,...N, for some random N with
	// at least 2000 so the queue builds up a bit.
	atLeast := 2000
	count := atLeast + rand.Intn(3000-atLeast)
	fmt.Printf("%s: Starting upload of %d certificates ....\n", t.prefix, count)
	for i := 1; i <= count; i++ {
		chain, err := generator.CertChain()
		if err != nil {
			return err
		}
		_, err = t.client().AddChain(ctx, chain)
		t.stats.expect(ctfe.AddChainName, 200)
		if err != nil {
			return fmt.Errorf("got AddChain(int-ca.cert)=(nil,%v); want (_,nil)", err)
		}
	}
	fmt.Printf("%s: Upload of %d certificates complete\n", t.prefix, count)

	// Stage 3: Set the log to DRAINING using the admin server.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	if err := setTreeState(ctx, t.adminServer, t.cfg.LogId, trillian.TreeState_DRAINING); err != nil {
		return fmt.Errorf("setTreeState(DRAINING)=%v, want: nil", err)
	}

	// Stage 4a: Get an updated STH. We'll use this point for a consistency
	// proof later.
	sth1, err := t.client().GetSTH(ctx)
	t.stats.expect(ctfe.GetSTHName, 200)
	if err != nil {
		return fmt.Errorf("got GetSTH(DRAINING)=(nil,%v); want (_,nil)", err)
	}
	if sth1.Version != 0 {
		return fmt.Errorf("sth.Version=%v; want V1(0)", sth1.Version)
	}
	fmt.Printf("%s: Got STH(time=%q, size=%d): roothash=%x\n", t.prefix, timeFromMS(sth1.Timestamp), sth1.TreeSize, sth1.SHA256RootHash)

	// Stage 4b: Wait for the queue to drain and everything to be integrated.
	sth2, err := t.awaitTreeSize(context.Background(), uint64(count), true, mmd)
	if err != nil {
		return err
	}
	fmt.Printf("%s: Got STH(time=%q, size=%d): roothash=%x\n", t.prefix, timeFromMS(sth2.Timestamp), sth2.TreeSize, sth2.SHA256RootHash)

	// Stage 5. Get a consistency proof from sth1 to sth2 and verify it.
	proof, err := t.client().GetSTHConsistency(ctx, sth1.TreeSize, sth2.TreeSize)
	t.stats.expect(ctfe.GetSTHConsistencyName, 200)
	if err != nil {
		return err
	}
	if err := t.checkCTConsistencyProof(sth1, sth2, proof); err != nil {
		return err
	}
	fmt.Printf("%s: VerifiedConsistency(time=%q, size1=%d, size2=%d): final roothash=%x\n", t.prefix, timeFromMS(sth2.Timestamp), sth1.TreeSize, sth2.TreeSize, sth2.SHA256RootHash)

	// Stage 6. Try to submit a chain and it should be rejected with 403.
	_, err = t.client().AddChain(ctx, caChain)
	t.stats.expect(ctfe.AddChainName, 403)
	if err == nil || !strings.Contains(err.Error(), "403") {
		return fmt.Errorf("got AddChain(DRAINING: int-ca.cert)=(nil,%v); want (_,err inc. 403)", err)
	}

	// Stage 7a - Set the log state back to ACTIVE and submit again. This should
	// be accepted.
	ctx, cancel = context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	if err := setTreeState(ctx, t.adminServer, t.cfg.LogId, trillian.TreeState_ACTIVE); err != nil {
		return fmt.Errorf("setTreeState(ACTIVE)=%v, want: nil", err)
	}
	_, err = t.client().AddChain(ctx, caChain)
	t.stats.expect(ctfe.AddChainName, 200)
	if err != nil {
		return fmt.Errorf("got AddChain(ACTIVE: int-ca.cert)=(nil,%v); want (_,nil)", err)
	}

	// Stage 7b: Wait for that new certificate to be integrated.
	sthCaCert, err := t.awaitTreeSize(context.Background(), uint64(count+1), true, mmd)
	if err != nil {
		return err
	}
	fmt.Printf("%s: Got STH(time=%q, size=%d): roothash=%x\n", t.prefix, timeFromMS(sthCaCert.Timestamp), sthCaCert.TreeSize, sthCaCert.SHA256RootHash)

	// Stage 8 - Set the log to FROZEN using the admin server.
	ctx, cancel = context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	if err := setTreeState(ctx, t.adminServer, t.cfg.LogId, trillian.TreeState_FROZEN); err != nil {
		return fmt.Errorf("setTreeState(FROZEN)=%v, want: nil", err)
	}

	// Stage 9 - Try to upload the pre-cert again and it should be rejected
	// with FORBIDDEN status.
	_, err = t.client().AddChain(ctx, caChain)
	t.stats.expect(ctfe.AddChainName, 403)
	if err == nil || !strings.Contains(err.Error(), "403") {
		return fmt.Errorf("got AddChain(FROZEN: int-ca.cert)=(nil,%v); want (_,err inc. 403)", err)
	}

	// Stage 10 - Obtain latest STH and check it hasn't increased in size since
	// the last submission.
	sth3, err := t.client().GetSTH(ctx)
	t.stats.expect(ctfe.GetSTHName, 200)
	if err != nil {
		return fmt.Errorf("got GetSTH(FROZEN)=(nil,%v); want (_,nil)", err)
	}

	// We know that anything queued was integrated so is should be impossible
	// that the tree has grown. There is one extra certificate from the test
	// that we could submit in Stage 7a.
	if sth2.TreeSize+1 != sth3.TreeSize {
		return fmt.Errorf("sth3 got TreeSize=%d, want: %d", sth3.TreeSize, sth2.TreeSize)
	}

	// Final stats check.
	if err := t.checkStats(); err != nil {
		return fmt.Errorf("stats check failed: %v", err)
	}

	return nil
}

// timeFromMS converts a timestamp in milliseconds (as used in CT) to a time.Time.
func timeFromMS(ts uint64) time.Time {
	secs := int64(ts / 1000)
	msecs := int64(ts % 1000)
	return time.Unix(secs, msecs*1000000)
}

// GetChain retrieves a certificate from a file of the given name and directory.
func GetChain(dir, path string) ([]ct.ASN1Cert, error) {
	certdata, err := os.ReadFile(filepath.Join(dir, path))
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %v", err)
	}
	return CertsFromPEM(certdata), nil
}

// CertsFromPEM loads X.509 certificates from the provided PEM-encoded data.
func CertsFromPEM(data []byte) []ct.ASN1Cert {
	var chain []ct.ASN1Cert
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			chain = append(chain, ct.ASN1Cert{Data: block.Bytes})
		}
	}
	return chain
}

// checkCTConsistencyProof checks the given consistency proof.
func (t *testInfo) checkCTConsistencyProof(sth1, sth2 *ct.SignedTreeHead, pf [][]byte) error {
	return proof.VerifyConsistency(t.hasher, sth1.TreeSize, sth2.TreeSize, pf, sth1.SHA256RootHash[:], sth2.SHA256RootHash[:])
}

// buildNewPrecertData creates a new pre-certificate based on the given template cert (which is
// modified)
func buildNewPrecertData(cert, issuer *x509.Certificate, signer crypto.Signer) ([]byte, error) {
	// Randomize the subject key ID.
	randData := make([]byte, 128)
	if _, err := cryptorand.Read(randData); err != nil {
		return nil, fmt.Errorf("failed to read random data: %v", err)
	}
	cert.SubjectKeyId = randData

	// Add the CT poison extension.
	cert.ExtraExtensions = append(cert.ExtraExtensions, pkix.Extension{
		Id:       x509.OIDExtensionCTPoison,
		Critical: true,
		Value:    []byte{0x05, 0x00}, // ASN.1 NULL
	})

	// Create a fresh certificate, signed by the issuer.
	cert.AuthorityKeyId = issuer.SubjectKeyId
	data, err := x509.CreateCertificate(cryptorand.Reader, cert, issuer, cert.PublicKey, signer)
	if err != nil {
		return nil, fmt.Errorf("failed to CreateCertificate: %v", err)
	}
	return data, nil
}

// MakeSigner creates a signer using the private key in the test directory.
func MakeSigner(testDir string) (crypto.Signer, error) {
	fileName := filepath.Join(testDir, "int-ca.privkey.pem")
	keyPEM, err := os.ReadFile(fileName)
	if err != nil {
		return nil, fmt.Errorf("error reading file %q: %w", fileName, err)
	}

	block, _ := pem.Decode(keyPEM)
	decPEM, err := x509.DecryptPEMBlock(block, []byte("babelfish"))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt file %q: %w", fileName, err)
	}

	key, err := x509.ParseECPrivateKey(decPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key for re-signing: %v", err)
	}
	return key, nil
}

// Track HTTP requests/responses so we can check the stats exported by the log.
type logStats struct {
	logID int64
	reqs  map[string]int            // entrypoint =>count
	rsps  map[string]map[string]int // entrypoint => status => count

}

func newLogStats(logID int64) *logStats {
	stats := logStats{
		logID: logID,
		reqs:  make(map[string]int),
		rsps:  make(map[string]map[string]int),
	}
	for _, ep := range ctfe.Entrypoints {
		stats.rsps[string(ep)] = make(map[string]int)
	}
	return &stats
}

func (ls *logStats) expect(ep ctfe.EntrypointName, rc int) {
	if ls == nil {
		return
	}
	ls.reqs[string(ep)]++
	ls.rsps[string(ep)][strconv.Itoa(rc)]++
}

func (ls *logStats) fromServer(ctx context.Context, servers string) (*logStats, error) {
	reqsRE := regexp.MustCompile(reqStatsRE)
	rspsRE := regexp.MustCompile(rspStatsRE)

	got := newLogStats(int64(ls.logID))
	for _, s := range strings.Split(servers, ",") {
		httpReq, err := http.NewRequest(http.MethodGet, "http://"+s+"/metrics", nil)
		if err != nil {
			return nil, fmt.Errorf("failed to build GET request: %v", err)
		}
		c := new(http.Client)

		httpRsp, err := ctxhttp.Do(ctx, c, httpReq)
		if err != nil {
			return nil, fmt.Errorf("getting stats failed: %v", err)
		}
		defer httpRsp.Body.Close()
		defer io.ReadAll(httpRsp.Body)
		if httpRsp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("got HTTP Status %q", httpRsp.Status)
		}

		scanner := bufio.NewScanner(httpRsp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			m := reqsRE.FindStringSubmatch(line)
			if m != nil {
				if m[2] == strconv.FormatInt(ls.logID, 10) {
					if val, err := strconv.ParseFloat(m[3], 64); err == nil {
						ep := m[1]
						got.reqs[ep] += int(val)
					}
				}
				continue
			}
			m = rspsRE.FindStringSubmatch(line)
			if m != nil {
				if m[2] == strconv.FormatInt(ls.logID, 10) {
					if val, err := strconv.ParseFloat(m[4], 64); err == nil {
						ep := m[1]
						rc := m[3]
						got.rsps[ep][rc] += int(val)
					}
				}
				continue
			}
		}
	}

	return got, nil
}

func (ls *logStats) check(cfg *configpb.LogConfig, servers string) error {
	if ls == nil {
		return nil
	}
	ctx := context.Background()
	got, err := ls.fromServer(ctx, servers)
	if err != nil {
		return err
	}
	// Now compare accumulated actual stats with what we expect to see.
	if !reflect.DeepEqual(got.reqs, ls.reqs) {
		return fmt.Errorf("got reqs %+v; want %+v", got.reqs, ls.reqs)
	}
	if !reflect.DeepEqual(got.rsps, ls.rsps) {
		return fmt.Errorf("got rsps %+v; want %+v", got.rsps, ls.rsps)
	}
	return nil
}

func setTreeState(ctx context.Context, adminServer string, logID int64, state trillian.TreeState) error {
	treeStateMask := &fieldmaskpb.FieldMask{
		Paths: []string{"tree_state"},
	}

	req := &trillian.UpdateTreeRequest{
		Tree: &trillian.Tree{
			TreeId:    logID,
			TreeState: state,
		},
		UpdateMask: treeStateMask,
	}

	conn, err := grpc.Dial(adminServer, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	defer conn.Close()

	adminClient := trillian.NewTrillianAdminClient(conn)
	_, err = adminClient.UpdateTree(ctx, req)
	if err != nil {
		return err
	}
	return nil
}

// NotAfterForLog returns a NotAfter time to be used for certs submitted
// to the given log instance, allowing for any temporal shard configuration.
func NotAfterForLog(c *configpb.LogConfig) (time.Time, error) {
	if c.NotAfterStart == nil && c.NotAfterLimit == nil {
		return time.Now().Add(24 * time.Hour), nil
	}

	if c.NotAfterStart != nil {
		if err := c.NotAfterStart.CheckValid(); err != nil {
			return time.Time{}, fmt.Errorf("failed to parse NotAfterStart: %v", err)
		}
		start := c.NotAfterStart.AsTime()
		if c.NotAfterLimit == nil {
			return start.Add(24 * time.Hour), nil
		}

		if err := c.NotAfterLimit.CheckValid(); err != nil {
			return time.Time{}, fmt.Errorf("failed to parse NotAfterLimit: %v", err)
		}
		limit := c.NotAfterLimit.AsTime()
		midDelta := limit.Sub(start) / 2
		return start.Add(midDelta), nil
	}

	if err := c.NotAfterLimit.CheckValid(); err != nil {
		return time.Time{}, fmt.Errorf("failed to parse NotAfterLimit: %v", err)
	}
	limit := c.NotAfterLimit.AsTime()
	return limit.Add(-1 * time.Hour), nil
}
