package ctdns

import (
	"context"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"regexp"
	"strconv"

	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go/trillian/ctfe"
	"github.com/google/certificate-transparency-go/trillian/ctfe/configpb"
	"github.com/google/trillian"
	"github.com/google/trillian/types"
	"github.com/miekg/dns"
)

const maxProofLen = 255

var (
	// In these formats the (.*) is always the zone, this is checked outside the
	// regex matching.
	sthRE     = regexp.MustCompile("^sth\\.(.*)\\.$")
	consistRE = regexp.MustCompile("^(\\d+)\\.(\\d+)\\.(\\d+)\\.sth-consistency\\.(.*)\\.$")
	hashRE    = regexp.MustCompile("^([A-Z0-9]+)\\.hash\\.(.*)\\.$")
	treeRE    = regexp.MustCompile("^(\\d+)\\.(\\d+)\\.(\\d+)\\.tree\\.(.*)\\.$")
)

type dnsFunc func(*CTDNSHandler, []string, dns.ResponseWriter, *dns.Msg)

type CTDNSHandler struct {
	client   trillian.TrillianLogClient
	cfg      *configpb.LogConfig
	opts     ctfe.InstanceOptions
	handlers []dnsHandler
}

type dnsHandler struct {
	matchRE  *regexp.Regexp
	handleFn dnsFunc
}

func New(client trillian.TrillianLogClient, cfg *configpb.LogConfig, opts ctfe.InstanceOptions) dns.Handler {
	return &CTDNSHandler{
		client: client,
		cfg:    cfg,
		opts:   opts,
		handlers: []dnsHandler{
			{matchRE: sthRE, handleFn: sthFunc},
			{matchRE: consistRE, handleFn: consistFunc},
			{matchRE: hashRE, handleFn: hashFunc},
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

	glog.Infof("In Query: %v", r.Question[0].Name)
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
	ctx, cancelFunc := context.WithTimeout(context.Background(), c.opts.Deadline)
	defer cancelFunc()
	req := &trillian.GetLatestSignedLogRootRequest{LogId: c.cfg.LogId}
	resp, err := c.client.GetLatestSignedLogRoot(ctx, req)
	if err != nil {
		glog.Warningf("sthFunc(): GetLatestSignedLogRoot=%v", err)
		m := r.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(m)
		return
	}

	// TODO(Martin2112): Verify signed log root?
	var logRoot types.LogRootV1
	if err := logRoot.UnmarshalBinary(resp.GetSignedLogRoot().GetLogRoot()); err != nil {
		glog.Warningf("sthFunc(): Unpack root=%v", err)
		failWithRcode(w, r, dns.RcodeServerFailure)
		return
	}

	rr := buildSTHResponse(params[0], &logRoot)
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
	var values [4]int64
	for i := 1; i < 4; i++ {
		v, err := strconv.Atoi(params[i])
		if err != nil {
			failWithRcode(w, r, dns.RcodeServerFailure)
			return
		}
		values[i] = int64(v)
	}
	ctx, cancelFunc := context.WithTimeout(context.Background(), c.opts.Deadline)
	defer cancelFunc()
	req := &trillian.GetConsistencyProofRequest{
		LogId:          c.cfg.LogId,
		FirstTreeSize:  values[2],
		SecondTreeSize: values[3]}
	resp, err := c.client.GetConsistencyProof(ctx, req)
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
	rr := buildConsistResponse(params[0], int(values[1]), resp.GetProof())
	m := new(dns.Msg)
	m.SetReply(r)
	m.Answer = append(m.Answer, rr)
	if err := w.WriteMsg(m); err != nil {
		glog.Warningf("sthFunc(): WriteMsg: %v", err)
	}

}

// params will contain 0 = regex match text 1 = base32 hash, 2 = zone.
func hashFunc(c *CTDNSHandler, params []string, w dns.ResponseWriter, r *dns.Msg) {
	h, err := base32.StdEncoding.DecodeString(params[1])
	if err != nil {
		failWithRcode(w, r, dns.RcodeServerFailure)
		return
	}
	ctx, cancelFunc := context.WithTimeout(context.Background(), c.opts.Deadline)
	defer cancelFunc()
	req := &trillian.GetLeavesByHashRequest{
		LogId:    c.cfg.LogId,
		LeafHash: [][]byte{h},
	}
	resp, err := c.client.GetLeavesByHash(ctx, req)
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
		glog.Warningf("sthFunc(): WriteMsg: %v", err)
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

func buildConsistResponse(q string, s int, proof *trillian.Proof) dns.RR {
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

func buildSTHResponse(q string, root *types.LogRootV1) dns.RR {
	rh := base64.StdEncoding.EncodeToString(root.RootHash)
	ths := "todo" // We don't store this so will need to re-sign like CTFE
	txt := fmt.Sprintf("%d.%d.%s.%s", root.TreeSize, root.TimestampNanos, rh, ths)

	// Response TXT has 4 fields: tree_size in ASCII decimal,
	// timestamp in ASCII decimal, sha256_root_hash in base64,
	// tree_head_signature in base64
	rr := &dns.TXT{
		Hdr: dns.RR_Header{Name: dns.Fqdn(q), Class: dns.ClassINET, Rrtype: dns.TypeTXT, Ttl: 0},
		Txt: []string{txt},
	}

	return rr
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

func failWithRcode(w dns.ResponseWriter, r *dns.Msg, rCode int) {
	m := new(dns.Msg)
	m = m.SetRcode(r, rCode)
	if err := w.WriteMsg(m); err != nil {
		glog.Warningf("Failed to write error code: %v, err=%v", rCode, err)
	}
}
