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

// These handlers implement the CT over DNS proposal documented at:
// https://github.com/google/certificate-transparency-rfcs/blob/master/dns/draft-ct-over-dns.md

package ctdns

import (
	"context"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/golang/glog"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/trillian/ctfe/configpb"
	"github.com/miekg/dns"
)

// The maximum length of the text returned in a DNS consistency or inclusion
// proof response.
const maxProofLen = 255

// The client omits the padding from the hash query so we need to add it back.
const base32LeafPad = "===="

const (
	// Used for STH responses, which change over time.
	sthTTL = 5 * 60
	// Used for other responses, which are immutable
	respTTL = 24 * 60 * 60
)

var (
	// In these formats the last (.*) is always the zone, this is checked outside
	// the regex matching.
	sthRE     = regexp.MustCompile(`(?i)^sth\.(.*)\.$`)
	consistRE = regexp.MustCompile(`(?i)^(\d+)\.(\d+)\.(\d+)\.sth-consistency\.(.*)\.$`)
	hashRE    = regexp.MustCompile(`(?i)^([A-Z0-9]+)\.hash\.(.*)\.$`)
	treeRE    = regexp.MustCompile(`(?i)^(\d+)\.(\d+)\.(\d+)\.tree\.(.*)\.$`)
)

// DNSLogClient is the subset of client.LogClient required for the DNS
// server -> CTFE interactions.
type DNSLogClient interface {
	GetSTH(context.Context) (*ct.SignedTreeHead, error)
	GetSTHConsistency(ctx context.Context, first, second uint64) ([][]byte, error)
	GetProofByHash(ctx context.Context, hash []byte, treeSize uint64) (*ct.GetProofByHashResponse, error)
	GetEntryAndProof(ctx context.Context, index, treeSize uint64) (*ct.GetEntryAndProofResponse, error)
}

type dnsFunc func(context.Context, DNSLogClient, []string, dns.ResponseWriter, *dns.Msg)

// Handler encapsulates all the logic for serving CT related DNS
// requests.
type Handler struct {
	cfg      *configpb.LogConfig
	client   DNSLogClient
	baseURI  string
	opts     jsonclient.Options
	timeout  time.Duration
	handlers []dnsHandler
}

type dnsHandler struct {
	matchRE  *regexp.Regexp
	handleFn dnsFunc
}

// New creates a new DNS handler.
func New(cfg *configpb.LogConfig, baseURI string, client DNSLogClient, timeout time.Duration) dns.Handler {
	return &Handler{
		cfg:     cfg,
		baseURI: baseURI,
		client:  client,
		timeout: timeout,
		handlers: []dnsHandler{
			{matchRE: sthRE, handleFn: sthFunc},
			{matchRE: consistRE, handleFn: consistFunc},
			{matchRE: hashRE, handleFn: hashFunc},
			{matchRE: treeRE, handleFn: treeFunc},
		},
	}
}

// ServeDNS implements the dns.Handler interface and is the main serving
// API.
func (c *Handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	// From the spec all requests must be class INET, type TXT.
	if err := validate(r); err != nil {
		glog.Warningf("Handler.ServeDNS(): %v", err)
		// Request succeeded, we just don't have anything to return for that
		// class / type.
		failWithRcode(w, r, dns.RcodeSuccess, err)
		return
	}

	glog.V(1).Infof("Handler.ServeDNS(): Query: %v", r.Question[0].Name)
	q := dns.Fqdn(r.Question[0].Name)
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	// Find the first handler that accepts the name pattern match.
	for _, h := range c.handlers {
		params := h.matchRE.FindStringSubmatch(q)
		// All our matches should include at least the zone as a capture group
		// so we must have at least two results from the above.
		if len(params) > 1 {
			// Additionally check that the zone matched the last regex param and the
			// whole string matched to avoid any false positives. We don't just
			// force everything to lower case because the base32 encoding is
			// defined using upper case.
			if strings.ToLower(params[0]) == strings.ToLower(q) &&
				strings.ToLower(params[len(params)-1]) == strings.ToLower(c.cfg.DnsZone) {
				// This handler accepted the match and provides the result.
				h.handleFn(ctx, c.client, params, w, r)
				return
			}
		}
	}
	// If it's for our zone but anything else we don't know about it, but it's
	// not an error.
	if strings.HasSuffix(q, "."+strings.ToLower(dns.Fqdn(c.cfg.DnsZone))) {
		failWithRcode(w, r, dns.RcodeSuccess, nil)
		return
	}
	// No handler matched and not our zone. Reject the request.
	failWithRcode(w, r, dns.RcodeNotZone, nil)
}

func sthFunc(ctx context.Context, lc DNSLogClient, params []string, w dns.ResponseWriter, r *dns.Msg) {
	sth, err := lc.GetSTH(ctx)
	if err != nil {
		glog.Warningf("sthFunc(): GetSTH=%v", err)
		failWithRcode(w, r, dns.RcodeServerFailure, err)
		return
	}

	rr, err := buildSTHResponse(params[0], sth)
	if err != nil {
		failWithRcode(w, r, dns.RcodeServerFailure, err)
		return
	}
	m := new(dns.Msg)
	m.SetReply(r)
	m.Answer = append(m.Answer, rr)
	if err := w.WriteMsg(m); err != nil {
		glog.Warningf("sthFunc(): WriteMsg: %v", err)
	}
}

// params will contain 0 = regex match text, 1 = start_index, 2 = first, 3 = second
// 4 = zone.
func consistFunc(ctx context.Context, lc DNSLogClient, params []string, w dns.ResponseWriter, r *dns.Msg) {
	// We don't expect these to fail as the regex matched digits but check anyway.
	values, err := parseUints(params, 1, 4)
	if err != nil {
		failWithRcode(w, r, dns.RcodeServerFailure, err)
		return
	}
	proof, err := lc.GetSTHConsistency(ctx, values[2], values[3])
	if err != nil {
		glog.Warningf("consistFunc(): GetSTHConsistency=%v", err)
		failWithRcode(w, r, dns.RcodeServerFailure, err)
		return
	}
	// Ensure the client requested a valid start index for the proof.
	if values[1] >= uint64(len(proof)) {
		failWithRcode(w, r, dns.RcodeServerFailure, err)
		return
	}
	rr := buildProofResponse(params[0], int(values[1]), proof)
	m := new(dns.Msg)
	m.SetReply(r)
	m.Answer = append(m.Answer, rr)
	if err := w.WriteMsg(m); err != nil {
		glog.Warningf("consistFunc(): WriteMsg: %v", err)
	}
}

// params will contain 0 = regex match text, 1 = base32 hash, 2 = zone.
func hashFunc(ctx context.Context, lc DNSLogClient, params []string, w dns.ResponseWriter, r *dns.Msg) {
	h, err := base32.StdEncoding.DecodeString(params[1] + base32LeafPad)
	if err != nil {
		failWithRcode(w, r, dns.RcodeServerFailure, err)
		return
	}
	// Sadly we need to obtain a tree size as it's not included in the DNS
	// request.
	sth, err := lc.GetSTH(ctx)
	if err != nil {
		glog.Warningf("hashFunc(): GetSTH=%v", err)
		failWithRcode(w, r, dns.RcodeServerFailure, err)
		return
	}
	resp, err := lc.GetProofByHash(ctx, h, sth.TreeSize)
	if err != nil {
		glog.Warningf("hashFunc(): GetProofByHash=%v, %v", resp, err)
		failWithRcode(w, r, dns.RcodeServerFailure, err)
		return
	}
	rr := buildHashResponse(params[0], resp.LeafIndex)
	m := new(dns.Msg)
	m.SetReply(r)
	m.Answer = append(m.Answer, rr)
	if err := w.WriteMsg(m); err != nil {
		glog.Warningf("hashFunc(): WriteMsg: %v", err)
	}
}

// params will contain 0 = regex match text, 1 = start index, 2 = leaf_index,
// 3 = tree_size, 4 = zone.
func treeFunc(ctx context.Context, lc DNSLogClient, params []string, w dns.ResponseWriter, r *dns.Msg) {
	// We don't expect these to fail as the regex matched digits but check anyway.
	values, err := parseUints(params, 1, 4)
	if err != nil {
		failWithRcode(w, r, dns.RcodeServerFailure, err)
		return
	}
	resp, err := lc.GetEntryAndProof(ctx, values[2], values[3])
	if err != nil {
		glog.Warningf("treeFunc(): GetEntryAndProof=%v, %v", resp, err)
		failWithRcode(w, r, dns.RcodeServerFailure, err)
		return
	}
	// Ensure the client requested a valid start index for the proof.
	if values[1] >= uint64(len(resp.AuditPath)) {
		failWithRcode(w, r, dns.RcodeServerFailure, err)
		return
	}
	rr := buildProofResponse(params[0], int(values[1]), resp.AuditPath)
	m := new(dns.Msg)
	m.SetReply(r)
	m.Answer = append(m.Answer, rr)
	if err := w.WriteMsg(m); err != nil {
		glog.Warningf("treeFunc(): WriteMsg: %v", err)
	}
}

func buildHashResponse(q string, index int64) dns.RR {
	// Response has one element, the leaf index.
	rr := &dns.TXT{
		Hdr: dns.RR_Header{Name: dns.Fqdn(q), Class: dns.ClassINET, Rrtype: dns.TypeTXT, Ttl: respTTL},
		Txt: []string{fmt.Sprintf("%d", index)},
	}

	return rr
}

func buildProofResponse(q string, s int, proof [][]byte) dns.RR {
	var p []byte
	// We can pack a limited number of proof elements into the dns response.
	for i := s; i < len(proof); i++ {
		if len(p)+len(proof[i]) > maxProofLen {
			break
		}
		p = append(p, proof[i]...)
	}
	// Response has one element. Note that the response is binary and not encoded.
	rr := &dns.TXT{
		Hdr: dns.RR_Header{Name: dns.Fqdn(q), Class: dns.ClassINET, Rrtype: dns.TypeTXT, Ttl: respTTL},
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
	// Response TXT has 4 fields: tree_size in ASCII decimal,
	// timestamp in ASCII decimal, sha256_root_hash in base64,
	// tree_head_signature in base64
	txt := fmt.Sprintf("%d.%d.%s.%s", root.TreeSize, ts, rh, ths)
	rr := &dns.TXT{
		Hdr: dns.RR_Header{Name: dns.Fqdn(q), Class: dns.ClassINET, Rrtype: dns.TypeTXT, Ttl: sthTTL},
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

func parseUints(p []string, first, last int) ([]uint64, error) {
	var values = make([]uint64, last)
	for i := first; i < last; i++ {
		v, err := strconv.Atoi(p[i])
		if err != nil {
			return nil, err
		}
		values[i] = uint64(v)
	}

	return values, nil
}

func failWithRcode(w dns.ResponseWriter, r *dns.Msg, rCode int, err error) {
	m := new(dns.Msg)
	m = m.SetRcode(r, rCode)
	if err != nil {
		glog.Warningf("Request failed because of error: %v", err)
	}
	if err := w.WriteMsg(m); err != nil {
		glog.Warningf("Failed to write error code: %v, err=%v", rCode, err)
	}
}
