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

// These handlers implement the CT over DNS proposal documented at:
// https://github.com/google/certificate-transparency-rfcs/blob/master/dns/draft-ct-over-dns.md

package ctfe

import (
	"context"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"regexp"
	"strconv"

	"github.com/golang/glog"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/trillian/ctfe/configpb"
	"github.com/google/trillian"
	"github.com/miekg/dns"
)

// The maximum length of the text returned in a DNS consistency or inclusion
// proof response.
const maxProofLen = 255

var (
	// In these formats the last (.*) is always the zone, this is checked outside
	// the regex matching.
	sthRE     = regexp.MustCompile("^sth\\.(.*)\\.$")
	consistRE = regexp.MustCompile("^(\\d+)\\.(\\d+)\\.(\\d+)\\.sth-consistency\\.(.*)\\.$")
	hashRE    = regexp.MustCompile("^([A-Z0-9]+)\\.hash\\.(.*)\\.$")
	treeRE    = regexp.MustCompile("^(\\d+)\\.(\\d+)\\.(\\d+)\\.tree\\.(.*)\\.$")
)

type dnsFunc func(*CTDNSHandler, []string, dns.ResponseWriter, *dns.Msg)

type CTDNSHandler struct {
	cfg      *configpb.LogConfig
	logCtx   *LogContext
	handlers []dnsHandler
}

type dnsHandler struct {
	matchRE  *regexp.Regexp
	handleFn dnsFunc
}

func NewDNS(cfg *configpb.LogConfig, logCtx *LogContext) dns.Handler {
	return &CTDNSHandler{
		cfg:    cfg,
		logCtx: logCtx,
		handlers: []dnsHandler{
			{matchRE: sthRE, handleFn: sthFunc},
			{matchRE: consistRE, handleFn: consistFunc},
			{matchRE: hashRE, handleFn: hashFunc},
			{matchRE: treeRE, handleFn: treeFunc},
		},
	}
}

func (c *CTDNSHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	// From the spec all requests must be class INET, type TXT.
	if err := validate(r); err != nil {
		glog.Warningf("CTDNSHandler.ServeDNS(): %v", err)
		failWithRcode(w, r, dns.RcodeFormatError)
		return
	}

	glog.V(1).Infof("CTDNSHandler.ServeDNS(): Query: %v", r.Question[0].Name)
	q := dns.Fqdn(r.Question[0].Name)

	// Find the first handler that accepts the name pattern match.
	for _, h := range c.handlers {
		params := h.matchRE.FindStringSubmatch(q)
		// All our matches should include at least the zone as a capture group
		// so we must have at least two results from the above.
		if len(params) > 1 {
			// Additionally check that the zone matched the last regex param and the
			// whole string matched to avoid any false positives.
			if params[0] == q && params[len(params)-1] == c.cfg.DnsZone {
				// This handler accepted the match and provides the result.
				h.handleFn(c, params, w, r)
				return
			}
		}
	}
	// No handler matched. Reject the request.
	failWithRcode(w, r, dns.RcodeNotZone)
}

func sthFunc(c *CTDNSHandler, params []string, w dns.ResponseWriter, r *dns.Msg) {
	ctx, cancelFunc := context.WithTimeout(context.Background(), c.logCtx.instanceOpts.Deadline)
	defer cancelFunc()
	sth, err := GetTreeHead(ctx, c.logCtx.rpcClient, c.logCtx.logID, c.logCtx.LogPrefix)
	if err != nil {
		failWithRcode(w, r, dns.RcodeServerFailure)
		return
	}

	// Add the signature over the STH contents.
	err = c.logCtx.signV1TreeHead(c.logCtx.signer, sth)
	if err != nil || len(sth.TreeHeadSignature.Signature) == 0 {
		failWithRcode(w, r, dns.RcodeServerFailure)
		return
	}

	rr, err := buildSTHResponse(params[0], sth)
	if err != nil {
		failWithRcode(w, r, dns.RcodeServerFailure)
		return
	}
	m := new(dns.Msg)
	m.SetReply(r)
	m.Answer = append(m.Answer, rr)
	if err := w.WriteMsg(m); err != nil {
		glog.Warningf("sthFunc(): WriteMsg: %v", err)
	}
}

// params will contain 0 = regex match text 1 = start_index, 2 = first, 3 = second
// 4 = zone.
func consistFunc(c *CTDNSHandler, params []string, w dns.ResponseWriter, r *dns.Msg) {
	// We don't expect these to fail as the regex matched digits but check anyway.
	values, err := parseInts(params, 1, 4)
	if err != nil {
		failWithRcode(w, r, dns.RcodeServerFailure)
		return
	}
	ctx, cancelFunc := context.WithTimeout(context.Background(), c.logCtx.instanceOpts.Deadline)
	defer cancelFunc()
	req := &trillian.GetConsistencyProofRequest{
		LogId:          c.cfg.LogId,
		FirstTreeSize:  values[2],
		SecondTreeSize: values[3]}
	resp, err := c.logCtx.rpcClient.GetConsistencyProof(ctx, req)
	if err != nil {
		glog.Warningf("consistFunc(): GetConsistencyProofRequest=%v", err)
		failWithRcode(w, r, dns.RcodeServerFailure)
		return
	}
	// Ensure the client requested a valid start index for the proof.
	if values[1] < 0 || values[1] >= int64(len(resp.Proof.Hashes)) {
		failWithRcode(w, r, dns.RcodeServerFailure)
		return
	}
	rr := buildProofResponse(params[0], int(values[1]), resp.GetProof())
	m := new(dns.Msg)
	m.SetReply(r)
	m.Answer = append(m.Answer, rr)
	if err := w.WriteMsg(m); err != nil {
		glog.Warningf("consistFunc(): WriteMsg: %v", err)
	}
}

// params will contain 0 = regex match text 1 = base32 hash, 2 = zone.
func hashFunc(c *CTDNSHandler, params []string, w dns.ResponseWriter, r *dns.Msg) {
	h, err := base32.StdEncoding.DecodeString(params[1])
	if err != nil {
		failWithRcode(w, r, dns.RcodeServerFailure)
		return
	}
	ctx, cancelFunc := context.WithTimeout(context.Background(), c.logCtx.instanceOpts.Deadline)
	defer cancelFunc()
	req := &trillian.GetLeavesByHashRequest{
		LogId:    c.cfg.LogId,
		LeafHash: [][]byte{h},
	}
	resp, err := c.logCtx.rpcClient.GetLeavesByHash(ctx, req)
	if err != nil || len(resp.Leaves) != 1 {
		glog.Warningf("hashFunc(): GetLeavesByHashRequest=%v, %v", resp, err)
		failWithRcode(w, r, dns.RcodeServerFailure)
		return
	}
	rr := buildHashResponse(params[0], resp.Leaves[0])
	m := new(dns.Msg)
	m.SetReply(r)
	m.Answer = append(m.Answer, rr)
	if err := w.WriteMsg(m); err != nil {
		glog.Warningf("hashFunc(): WriteMsg: %v", err)
	}
}

// params will contain 0 = regex match text, 1 = start index, 2 = leaf_index,
// 3 = tree_size, 4 = zone.
func treeFunc(c *CTDNSHandler, params []string, w dns.ResponseWriter, r *dns.Msg) {
	// We don't expect these to fail as the regex matched digits but check anyway.
	values, err := parseInts(params, 1, 4)
	if err != nil {
		failWithRcode(w, r, dns.RcodeServerFailure)
		return
	}
	ctx, cancelFunc := context.WithTimeout(context.Background(), c.logCtx.instanceOpts.Deadline)
	defer cancelFunc()
	req := &trillian.GetInclusionProofRequest{
		LogId:     c.cfg.LogId,
		LeafIndex: values[2],
		TreeSize:  values[3],
	}
	resp, err := c.logCtx.rpcClient.GetInclusionProof(ctx, req)
	if err != nil {
		glog.Warningf("hashFunc(): GetInclusionProof=%v, %v", resp, err)
		failWithRcode(w, r, dns.RcodeServerFailure)
		return
	}
	// Ensure the client requested a valid start index for the proof.
	if values[1] < 0 || values[1] >= int64(len(resp.Proof.Hashes)) {
		failWithRcode(w, r, dns.RcodeServerFailure)
		return
	}
	rr := buildProofResponse(params[0], int(values[1]), resp.GetProof())
	m := new(dns.Msg)
	m.SetReply(r)
	m.Answer = append(m.Answer, rr)
	if err := w.WriteMsg(m); err != nil {
		glog.Warningf("treeFunc(): WriteMsg: %v", err)
	}
}

func buildHashResponse(q string, l *trillian.LogLeaf) dns.RR {
	// Response has one element, the leaf index.
	rr := &dns.TXT{
		Hdr: dns.RR_Header{Name: dns.Fqdn(q), Class: dns.ClassINET, Rrtype: dns.TypeTXT, Ttl: 0},
		Txt: []string{fmt.Sprintf("%d", l.LeafIndex)},
	}

	return rr
}

func buildProofResponse(q string, s int, proof *trillian.Proof) dns.RR {
	var p []byte
	// We can pack a limited number of proof elements into the dns response.
	for i := s; i < len(proof.Hashes); i++ {
		if len(p)+len(proof.Hashes[i]) > maxProofLen {
			break
		}
		p = append(p, proof.Hashes[i]...)
	}
	// Response has one element. Note that the response is binary and not encoded.
	rr := &dns.TXT{
		Hdr: dns.RR_Header{Name: dns.Fqdn(q), Class: dns.ClassINET, Rrtype: dns.TypeTXT, Ttl: 0},
		Txt: []string{string(p)},
	}

	return rr
}

func buildSTHResponse(q string, root *ct.SignedTreeHead) (dns.RR, error) {
	rh := base64.StdEncoding.EncodeToString(root.SHA256RootHash[:])
	ts := root.Timestamp
	sig, err := tls.Marshal(root.TreeHeadSignature)
	if err != nil {
		return nil, err
	}
	ths := base64.StdEncoding.EncodeToString(sig)
	txt := fmt.Sprintf("%d.%d.%s.%s", root.TreeSize, ts, rh, ths)

	// Response TXT has 4 fields: tree_size in ASCII decimal,
	// timestamp in ASCII decimal, sha256_root_hash in base64,
	// tree_head_signature in base64
	rr := &dns.TXT{
		Hdr: dns.RR_Header{Name: dns.Fqdn(q), Class: dns.ClassINET, Rrtype: dns.TypeTXT, Ttl: 0},
		Txt: []string{txt},
	}

	return rr, nil
}

func validate(r *dns.Msg) error {
	if r.Question[0].Qtype != dns.TypeTXT {
		return fmt.Errorf("Qtype=%v, want: TXT", r.Question[0].Qtype)
	}

	if r.Question[0].Qclass != dns.ClassINET {
		return fmt.Errorf("Qclass=%v, want: INET", r.Question[0].Qclass)
	}

	return nil
}

func parseInts(p []string, first, last int) ([]int64, error) {
	var values = make([]int64, last)
	for i := first; i < last; i++ {
		v, err := strconv.Atoi(p[i])
		if err != nil {
			return nil, err
		}
		values[i] = int64(v)
	}

	return values, nil
}

func failWithRcode(w dns.ResponseWriter, r *dns.Msg, rCode int) {
	m := new(dns.Msg)
	m = m.SetRcode(r, rCode)
	if err := w.WriteMsg(m); err != nil {
		glog.Warningf("Failed to write error code: %v, err=%v", rCode, err)
	}
}
