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

	"github.com/golang/protobuf/ptypes"
	"github.com/google/certificate-transparency-go/trillian/ctfe/configpb"
	"github.com/google/certificate-transparency-go/trillian/util"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/trillian"
	"github.com/google/trillian/crypto/keys"
	"github.com/google/trillian/monitoring"
)

var stringToKeyUsage = map[string]x509.ExtKeyUsage{
	"Any":                        x509.ExtKeyUsageAny,
	"ServerAuth":                 x509.ExtKeyUsageServerAuth,
	"ClientAuth":                 x509.ExtKeyUsageClientAuth,
	"CodeSigning":                x509.ExtKeyUsageCodeSigning,
	"EmailProtection":            x509.ExtKeyUsageEmailProtection,
	"IPSECEndSystem":             x509.ExtKeyUsageIPSECEndSystem,
	"IPSECTunnel":                x509.ExtKeyUsageIPSECTunnel,
	"IPSECUser":                  x509.ExtKeyUsageIPSECUser,
	"TimeStamping":               x509.ExtKeyUsageTimeStamping,
	"OCSPSigning":                x509.ExtKeyUsageOCSPSigning,
	"MicrosoftServerGatedCrypto": x509.ExtKeyUsageMicrosoftServerGatedCrypto,
	"NetscapeServerGatedCrypto":  x509.ExtKeyUsageNetscapeServerGatedCrypto,
}

// InstanceOptions describes the options for a log instance.
type InstanceOptions struct {
	// Config holds the original configuration options for the log.
	Config *configpb.LogConfig
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
}

// SetUpInstance sets up a log instance using the provided configuration, and
// returns a set of handlers for this log.
func SetUpInstance(ctx context.Context, opts InstanceOptions) (*PathHandlers, error) {
	logInfo, err := setUpLogInfo(ctx, opts)
	if err != nil {
		return nil, err
	}
	handlers := logInfo.Handlers(opts.Config.Prefix)
	return &handlers, nil
}

// SetUpMirrorInstance sets up a log mirror instance using the provided
// configuration, and returns a set of handlers for it.
func SetUpMirrorInstance(ctx context.Context, opts InstanceOptions, stor MirrorSTHStorage) (*PathHandlers, error) {
	logInfo, err := setUpLogInfo(ctx, opts)
	if err != nil {
		return nil, err
	}
	logInfo.sthGetter = &MirrorSTHGetter{li: logInfo, st: stor}
	handlers := logInfo.Handlers(opts.Config.Prefix)
	return &handlers, nil
}

func setUpLogInfo(ctx context.Context, opts InstanceOptions) (*logInfo, error) {
	cfg := opts.Config

	// Check config validity.
	if !cfg.IsMirror && len(cfg.RootsPemFile) == 0 {
		return nil, errors.New("need to specify RootsPemFile")
	}
	// Load the trusted roots
	roots := NewPEMCertPool()
	for _, pemFile := range cfg.RootsPemFile {
		if err := roots.AppendCertsFromPEMFile(pemFile); err != nil {
			return nil, fmt.Errorf("failed to read trusted roots: %v", err)
		}
	}

	var signer crypto.Signer
	if !cfg.IsMirror {
		if cfg.PrivateKey == nil {
			return nil, errors.New("need to specify PrivateKey")
		}
		// Load the private key for this log.
		var keyProto ptypes.DynamicAny
		if err := ptypes.UnmarshalAny(cfg.PrivateKey, &keyProto); err != nil {
			return nil, fmt.Errorf("failed to unmarshal cfg.PrivateKey: %v", err)
		}
		var err error
		if signer, err = keys.NewSigner(ctx, keyProto.Message); err != nil {
			return nil, fmt.Errorf("failed to load private key: %v", err)
		}
	} else {
		if cfg.PrivateKey != nil {
			return nil, errors.New("mirror needs no PrivateKey")
		}
		if cfg.PublicKey == nil {
			return nil, errors.New("need to specify PublicKey")
		}
	}

	var keyUsages []x509.ExtKeyUsage
	if len(cfg.ExtKeyUsages) > 0 {
		for _, kuStr := range cfg.ExtKeyUsages {
			if ku, present := stringToKeyUsage[kuStr]; present {
				keyUsages = append(keyUsages, ku)
			} else {
				return nil, fmt.Errorf("unknown extended key usage: %s", kuStr)
			}
		}
	} else {
		keyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	}

	var naStart, naLimit *time.Time

	if cfg.NotAfterStart != nil {
		t, err := ptypes.Timestamp(cfg.NotAfterStart)
		if err != nil {
			return nil, fmt.Errorf("invalid not_after_start: %v", err)
		}
		naStart = &t
	}
	if cfg.NotAfterLimit != nil {
		t, err := ptypes.Timestamp(cfg.NotAfterLimit)
		if err != nil {
			return nil, fmt.Errorf("invalid not_after_limit: %v", err)
		}
		naLimit = &t
	}

	validationOpts := CertValidationOpts{
		trustedRoots:  roots,
		rejectExpired: cfg.RejectExpired,
		notAfterStart: naStart,
		notAfterLimit: naLimit,
		acceptOnlyCA:  cfg.AcceptOnlyCa,
		extKeyUsages:  keyUsages,
	}

	logInfo := newLogInfo(opts, validationOpts, signer, new(util.SystemTimeSource))
	return logInfo, nil
}
