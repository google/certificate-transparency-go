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

package minimal

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/google/certificate-transparency-go/gossip/minimal/configpb"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"
	"github.com/google/trillian/crypto/keys"
	"github.com/google/trillian/monitoring"

	logclient "github.com/google/certificate-transparency-go/client"
	hubclient "github.com/google/trillian-examples/gossip/client"
)

const (
	defaultRateHz      = 1.0
	defaultMinInterval = 1 * time.Second
)

// NewGossiperFromFile creates a gossiper from the given filename, which should
// contain text-protobuf encoded configuration data, together with an optional
// http Client.
func NewGossiperFromFile(ctx context.Context, filename string, hc *http.Client, mf monitoring.MetricFactory) (*Gossiper, error) {
	return NewBoundaryGossiperFromFile(ctx, filename, hc, hc, mf)
}

// NewBoundaryGossiperFromFile creates a gossiper that uses different
// http.Client instances for source logs and destination hubs, for example to
// allow gossiping across (some kinds of) network boundaries.
func NewBoundaryGossiperFromFile(ctx context.Context, filename string, hcLog, hcHub *http.Client, mf monitoring.MetricFactory) (*Gossiper, error) {
	cfgBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var cfgProto configpb.GossipConfig
	if txtErr := proto.UnmarshalText(string(cfgBytes), &cfgProto); txtErr != nil {
		if binErr := proto.Unmarshal(cfgBytes, &cfgProto); binErr != nil {
			return nil, fmt.Errorf("failed to parse GossipConfig from %q as text protobuf (%v) or binary protobuf (%v)", filename, txtErr, binErr)
		}
	}

	cfg, err := NewBoundaryGossiper(ctx, &cfgProto, hcLog, hcHub, mf)
	if err != nil {
		return nil, fmt.Errorf("%s: config error: %v", filename, err)
	}
	return cfg, nil
}

// NewGossiper creates a gossiper from the given configuration protobuf and optional
// http client.
func NewGossiper(ctx context.Context, cfg *configpb.GossipConfig, hc *http.Client, mf monitoring.MetricFactory) (*Gossiper, error) {
	return NewBoundaryGossiper(ctx, cfg, hc, hc, mf)
}

// NewBoundaryGossiper creates a gossiper from the given configuration protobuf
// and a pair of http.Client instances for source logs and destination hubs,
// to allow (for example) gossiping across (some kinds of) network boundaries.
func NewBoundaryGossiper(ctx context.Context, cfg *configpb.GossipConfig, hcLog, hcHub *http.Client, mf monitoring.MetricFactory) (*Gossiper, error) {
	once.Do(func() { setupMetrics(mf) })
	if len(cfg.DestHub) == 0 {
		return nil, errors.New("no dest hub config found")
	}
	if len(cfg.SourceLog) == 0 {
		return nil, errors.New("no source log config found")
	}

	needPrivKey := false
	for _, destHub := range cfg.DestHub {
		if !destHub.IsHub {
			// Destinations include at least one CT Log, so need a private key
			// for cert generation for all such destinations.
			needPrivKey = true
			break
		}
	}

	var signer crypto.Signer
	var root *x509.Certificate
	if needPrivKey {
		if cfg.PrivateKey == nil {
			return nil, errors.New("no private key found")
		}
		var keyProto ptypes.DynamicAny
		if err := ptypes.UnmarshalAny(cfg.PrivateKey, &keyProto); err != nil {
			return nil, fmt.Errorf("failed to unmarshal cfg.PrivateKey: %v", err)
		}
		var err error
		signer, err = keys.NewSigner(ctx, keyProto.Message)
		if err != nil {
			return nil, fmt.Errorf("failed to load private key: %v", err)
		}

		root, err = x509util.CertificateFromPEM([]byte(cfg.RootCert))
		if err != nil {
			return nil, fmt.Errorf("failed to parse root cert: %v", err)
		}
	}

	allSTHsRate := 0.0
	srcs := make(map[string]*sourceLog)
	for _, lc := range cfg.SourceLog {
		base, err := logConfigFromProto(lc, hcLog)
		if err != nil {
			return nil, fmt.Errorf("failed to parse source log config for %q: %v", lc.Name, err)
		}
		if _, ok := srcs[base.Name]; ok {
			return nil, fmt.Errorf("duplicate source logs for name %q", base.Name)
		}
		glog.Infof("configured source log %s at %s (%+v)", base.Name, base.URL, base)
		srcs[base.Name] = &sourceLog{logConfig: *base}
		knownSourceLogs.Set(1.0, base.Name)

		// Assume that each source log has a new STH when polled.
		sthRate := defaultRateHz
		if base.MinInterval > 0 {
			sthRate = 1.0 / base.MinInterval.Seconds()
		}
		allSTHsRate += sthRate
	}
	dests := make(map[string]*destHub)
	for _, lc := range cfg.DestHub {
		hub, err := hubFromProto(lc, hcHub)
		if err != nil {
			return nil, fmt.Errorf("failed to parse dest hub config for %q: %v", lc.Name, err)
		}
		if _, ok := dests[hub.Name]; ok {
			return nil, fmt.Errorf("duplicate dest hubs for name %q", hub.Name)
		}
		glog.Infof("configured dest Hub %s at %s (%+v)", hub.Name, hub.URL, hub)
		dests[hub.Name] = hub
		isHub := 0.0
		if lc.IsHub {
			isHub = 1.0
		}
		destPureHub.Set(isHub, hub.Name)

		submitRate := defaultRateHz
		if hub.MinInterval > 0 {
			submitRate = 1.0 / hub.MinInterval.Seconds()
		}
		if allSTHsRate > submitRate {
			glog.Errorf("%s: Overall STH retrieval rate (%f Hz) higher than submission limit (%f Hz) for hub, retrieved STHs may be dropped", hub.Name, allSTHsRate, submitRate)
		}
	}

	return &Gossiper{
		signer:     signer,
		root:       root,
		dests:      dests,
		srcs:       srcs,
		bufferSize: int(cfg.BufferSize),
	}, nil
}

func logConfigFromProto(cfg *configpb.LogConfig, hc *http.Client) (*logConfig, error) {
	if cfg.Name == "" {
		return nil, errors.New("no log name provided")
	}
	interval, err := ptypes.Duration(cfg.MinReqInterval)
	if err != nil {
		return nil, fmt.Errorf("failed to parse MinReqInterval: %v", err)
	}
	if interval <= 0 {
		interval = defaultMinInterval
	}
	opts := jsonclient.Options{PublicKeyDER: cfg.PublicKey.GetDer(), UserAgent: "ct-go-gossip-client/1.0"}
	client, err := logclient.New(cfg.Url, hc, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create log client for %q: %v", cfg.Name, err)
	}
	if client.Verifier == nil {
		glog.Warningf("No public key provided for log %s, signature checks will be skipped", cfg.Name)
	}
	return &logConfig{
		Name:        cfg.Name,
		URL:         cfg.Url,
		Log:         client,
		MinInterval: interval,
	}, nil
}

func hubFromProto(cfg *configpb.HubConfig, hc *http.Client) (*destHub, error) {
	if cfg.Name == "" {
		return nil, errors.New("no source log name provided")
	}
	interval, err := ptypes.Duration(cfg.MinReqInterval)
	if err != nil {
		return nil, fmt.Errorf("failed to parse MinReqInterval: %v", err)
	}
	if interval <= 0 {
		interval = defaultMinInterval
	}
	var submitter hubSubmitter
	opts := jsonclient.Options{PublicKeyDER: cfg.PublicKey.GetDer(), UserAgent: "ct-go-gossip-hub/1.0"}
	if cfg.IsHub {
		cl, err := hubclient.New(cfg.Url, hc, opts)
		if err != nil {
			return nil, fmt.Errorf("failed to create hub client for %q: %v", cfg.Name, err)
		}
		if cl.Verifier == nil {
			glog.Warningf("No public key provided for hub %s, signature checks will be skipped", cfg.Name)
		}
		submitter = &pureHubSubmitter{cl}
	} else {
		cl, err := logclient.New(cfg.Url, hc, opts)
		if err != nil {
			return nil, fmt.Errorf("failed to create log client for %q: %v", cfg.Name, err)
		}
		if cl.Verifier == nil {
			glog.Warningf("No public key provided for CT log %s, signature checks will be skipped", cfg.Name)
		}
		submitter = &ctLogSubmitter{cl}
	}
	return &destHub{
		Name:              cfg.Name,
		URL:               cfg.Url,
		Submitter:         submitter,
		MinInterval:       interval,
		lastHubSubmission: make(map[string]time.Time),
	}, nil
}

func hubScannerFromProto(cfg *configpb.HubConfig, hc *http.Client) (*hubScanner, error) {
	if cfg.Name == "" {
		return nil, errors.New("no hub name provided")
	}
	interval, err := ptypes.Duration(cfg.MinReqInterval)
	if err != nil {
		return nil, fmt.Errorf("failed to parse MinReqInterval: %v", err)
	}
	opts := jsonclient.Options{PublicKeyDER: cfg.PublicKey.GetDer(), UserAgent: "ct-go-gossip-scanner/1.0"}

	var fetcher hubFetcher
	if cfg.IsHub {
		cl, err := hubclient.New(cfg.Url, hc, opts)
		if err != nil {
			return nil, fmt.Errorf("failed to create hub client for Gossip Hub %q: %v", cfg.Name, err)
		}
		if cl.Verifier == nil {
			glog.Warningf("No public key provided for Gossip Hub %s, signature checks will be skipped", cfg.Name)
		}
		fetcher = &gossipHubFetcher{Hub: cl}
	} else {
		cl, err := logclient.New(cfg.Url, hc, opts)
		if err != nil {
			return nil, fmt.Errorf("failed to create hub client for CT log %q: %v", cfg.Name, err)
		}
		if cl.Verifier == nil {
			glog.Warningf("No public key provided for CT log %s, signature checks will be skipped", cfg.Name)
		}
		fetcher = &ctHubFetcher{Log: cl}
	}
	return &hubScanner{
		Name:          cfg.Name,
		URL:           cfg.Url,
		MinInterval:   interval,
		cfgStartIndex: cfg.StartIndex,
		fetcher:       fetcher,
	}, nil
}
