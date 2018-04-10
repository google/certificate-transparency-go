package ctdns

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go/trillian/ctfe"
	"github.com/google/certificate-transparency-go/trillian/ctfe/configpb"
	"github.com/google/trillian"
	"github.com/google/trillian/types"
	"github.com/miekg/dns"
)

var (
	// In these formats the (.*) is the zone, this is checked outside the
	// regex matching.
	consistFmt = "^(\\d+)\\.(\\d+)\\.(\\d+)\\.sth-consistency\\.(.*)\\.$"
	hashFmt    = "^([A-Z0-9]+)\\.hash\\.(.*)\\.$"
	treeFmt    = "^(\\d+)\\.(\\d+)\\.(\\d+)\\.tree\\(.*)\\.$"
)

type CTDNSHandler struct {
	client trillian.TrillianLogClient
	cfg    *configpb.LogConfig
	opts   ctfe.InstanceOptions
}

type STHDNSHandler struct {
	CTDNSHandler
}

func NewSTH(client trillian.TrillianLogClient, cfg *configpb.LogConfig, opts ctfe.InstanceOptions) dns.Handler {
	return &STHDNSHandler{CTDNSHandler{client: client, cfg: cfg, opts: opts}}
}

func (c *STHDNSHandler) buildSTHResponse(q string, root *types.LogRootV1) dns.RR {
	rh := base64.StdEncoding.EncodeToString(root.RootHash)
	ths := "todo" // We don't store this so will need to re-sign like CTFE
	txt := fmt.Sprintf("%d.%d.%s.%s", root.TreeSize, root.TimestampNanos, rh, ths)

	// Response TXT has 4 fields: tree_size in ASCII decimal,
	// timestamp in ASCII decimal, sha256_root_hash in base64,
	// tree_head_signature in base64
	rr := &dns.TXT{
		Hdr: dns.RR_Header{Name: q, Class: dns.ClassINET, Rrtype: dns.TypeTXT, Ttl: 0},
		Txt: []string{txt},
	}

	return rr
}

func (c *STHDNSHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	sthQuery := "sth." + c.cfg.DnsZone + "."

	if err := validate(r); err != nil {
		glog.Warningf("STHDNSHandler.ServeDNS(): %v", err)
		m := r.SetRcode(r, dns.RcodeFormatError)
		w.WriteMsg(m)
		return
	}

	ctx, cancelFunc := context.WithTimeout(context.Background(), c.opts.Deadline)
	defer cancelFunc()
	req := &trillian.GetLatestSignedLogRootRequest{LogId: c.cfg.LogId}
	resp, err := c.client.GetLatestSignedLogRoot(ctx, req)
	if err != nil {
		glog.Warningf("STHDNSHandler.ServeDNS(): GetLatestSignedLogRoot=%v", err)
		m := r.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(m)
		return
	}

	// TODO(Martin2112): Verify signed log root?
	var logRoot types.LogRootV1
	if err := logRoot.UnmarshalBinary(resp.GetSignedLogRoot().GetLogRoot()); err != nil {
		glog.Warningf("STHDNSHandler.ServeDNS(): Unpack root=%v", err)
		m := r.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(m)
		return
	}

	rr := c.buildSTHResponse(sthQuery, &logRoot)
	glog.Infof("Returning: %v", rr)
	m := new(dns.Msg)
	m.SetReply(r)
	m.Answer = append(m.Answer, rr)
	if err := w.WriteMsg(m); err != nil {
		glog.Warningf("STHDNSHandler.ServeDNS(): WriteMsg: %v", err)
	}
}

func validate(r *dns.Msg) error {
	if r.Question[0].Qtype != dns.TypeTXT {
		return fmt.Errorf("Qtype=%v, want: TXT", r.Question[0].Qtype)
	}

	if r.Question[0].Qclass != dns.ClassINET {
		return fmt.Errorf("Qclass=%v, want: INET", r.Question[0].Qtype)
	}

	return nil
}
