// Copyright 2016 Google Inc. All Rights Reserved.
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
	"context"
	"crypto"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go/trillian/util"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/trillian"
	"github.com/google/trillian/crypto/keys"
	"github.com/google/trillian/monitoring"
)

// InstanceOptions describes the options for a log instance.
type InstanceOptions struct {
	// Validated holds the original configuration options for the log, and some
	// of its fields parsed as a result of validating it.
	Validated *ValidatedLogConfig
	// Client is a corresponding Trillian log client.
	Client trillian.TrillianLogClient
	// Deadline is a timeout for Trillian RPC requests.
	Deadline time.Duration
	// MetricFactory allows creating metrics.
	MetricFactory monitoring.MetricFactory
	// ErrorMapper converts an error from an RPC request to an HTTP status, plus
	// a boolean to indicate whether the conversion succeeded.
	ErrorMapper func(error) (int, bool)
	// RequestLog provides structured logging of CTFE requests.
	RequestLog RequestLog
	// RemoteUser returns a string representing the originating host for the
	// given request. This string will be used as a User quota key.
	// If unset, no quota will be requested for remote users.
	RemoteQuotaUser func(*http.Request) string
	// CertificateQuotaUser returns a string represeing the passed in
	// intermediate certificate. This string will be user as a User quota key for
	// the cert. Quota will be requested for each intermediate in an
	// add-[pre]-chain request so as to allow individual issers to be rate
	// limited. If unset, no quota will be requested for intermediate
	// certificates.
	CertificateQuotaUser func(*x509.Certificate) string
	// STHStorage provides STHs of a source log for the mirror. Only mirror
	// instances will use it, i.e. when IsMirror == true in the config. If it is
	// empty then the DefaultMirrorSTHStorage will be used.
	STHStorage MirrorSTHStorage
}

// Instance is a set up log/mirror instance. It must be created with the
// SetUpInstance call.
type Instance struct {
	Opts      InstanceOptions
	Handlers  PathHandlers
	STHGetter STHGetter
	li        *logInfo
}

// RunUpdateSTH regularly updates the internal STH for each log so our metrics
// stay up-to-date with any tree head changes that are not triggered by us.
func (i *Instance) RunUpdateSTH(ctx context.Context, period time.Duration) {
	c := i.Opts.Validated.Config
	ticker := time.NewTicker(period)
	glog.Infof("Start internal get-sth operations on %v (%d)", c.Prefix, c.LogId)
	for t := range ticker.C {
		glog.V(1).Infof("Tick at %v: force internal get-sth for %v (%d)", t, c.Prefix, c.LogId)
		_, err := i.li.getSTH(ctx)
		if err != nil {
			glog.Warningf("Failed to retrieve STH for %v (%d): %v", c.Prefix, c.LogId, err)
			if ctx.Err() != nil {
				break
			}
		}
	}
}

// SetUpInstance sets up a log (or log mirror) instance using the provided
// configuration, and returns an object containing a set of handlers for this
// log, and an STH getter.
func SetUpInstance(ctx context.Context, opts InstanceOptions) (*Instance, error) {
	logInfo, err := setUpLogInfo(ctx, opts)
	if err != nil {
		return nil, err
	}
	handlers := logInfo.Handlers(opts.Validated.Config.Prefix)
	return &Instance{Opts: opts, Handlers: handlers, STHGetter: logInfo.sthGetter, li: logInfo}, nil
}

func setUpLogInfo(ctx context.Context, opts InstanceOptions) (*logInfo, error) {
	vCfg := opts.Validated
	cfg := vCfg.Config

	// Check config validity.
	if !cfg.IsMirror && len(cfg.RootsPemFile) == 0 {
		return nil, errors.New("need to specify RootsPemFile")
	}
	// Load the trusted roots.
	roots := NewPEMCertPool()
	for _, pemFile := range cfg.RootsPemFile {
		if err := roots.AppendCertsFromPEMFile(pemFile); err != nil {
			return nil, fmt.Errorf("failed to read trusted roots: %v", err)
		}
	}

	var signer crypto.Signer
	if !cfg.IsMirror {
		var err error
		if signer, err = keys.NewSigner(ctx, vCfg.PrivKey.Message); err != nil {
			return nil, fmt.Errorf("failed to load private key: %v", err)
		}
	}

	validationOpts := CertValidationOpts{
		trustedRoots:    roots,
		rejectExpired:   cfg.RejectExpired,
		rejectUnexpired: cfg.RejectUnexpired,
		notAfterStart:   vCfg.NotAfterStart,
		notAfterLimit:   vCfg.NotAfterLimit,
		acceptOnlyCA:    cfg.AcceptOnlyCa,
		extKeyUsages:    vCfg.KeyUsages,
	}

	logInfo := newLogInfo(opts, validationOpts, signer, new(util.SystemTimeSource))
	return logInfo, nil
}
