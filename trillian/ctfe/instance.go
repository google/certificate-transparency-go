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
	"errors"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/google/certificate-transparency-go/trillian/ctfe/configpb"
	"github.com/google/certificate-transparency-go/trillian/util"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/trillian"
	"github.com/google/trillian/crypto"
	"github.com/google/trillian/crypto/keys"
	"github.com/google/trillian/monitoring"
)

// LogConfigFromFile creates a slice of LogConfig options from the given
// filename, which should contain text-protobuf encoded configuration data.
func LogConfigFromFile(filename string) ([]*configpb.LogConfig, error) {
	if len(filename) == 0 {
		return nil, errors.New("log config filename empty")
	}

	cfgText, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read log config: %v", err)
	}

	var cfg configpb.LogConfigSet
	if err := proto.UnmarshalText(string(cfgText), &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse log config: %v", err)
	}

	if len(cfg.Config) == 0 {
		return nil, errors.New("empty log config found")
	}
	return cfg.Config, nil
}

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

// SetUpInstance sets up a log instance that uses the specified client to communicate
// with the Trillian RPC back end.
func SetUpInstance(ctx context.Context, client trillian.TrillianLogClient, cfg *configpb.LogConfig, deadline time.Duration, mf monitoring.MetricFactory) (*PathHandlers, error) {
	// Check config validity.
	if len(cfg.RootsPemFile) == 0 {
		return nil, errors.New("need to specify RootsPemFile")
	}
	if cfg.PrivateKey == nil {
		return nil, errors.New("need to specify PrivateKey")
	}

	// Load the trusted roots
	roots := NewPEMCertPool()
	for _, pemFile := range cfg.RootsPemFile {
		if err := roots.AppendCertsFromPEMFile(pemFile); err != nil {
			return nil, fmt.Errorf("failed to read trusted roots: %v", err)
		}
	}

	// Load the private key for this log.
	var keyProto ptypes.DynamicAny
	if err := ptypes.UnmarshalAny(cfg.PrivateKey, &keyProto); err != nil {
		return nil, fmt.Errorf("failed to unmarshal cfg.PrivateKey: %v", err)
	}

	key, err := keys.NewSigner(ctx, keyProto.Message)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %v", err)
	}
	signer := crypto.NewSHA256Signer(key)

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
	// Create and register the handlers using the RPC client we just set up
	logCtx := NewLogContext(cfg.LogId, cfg.Prefix, validationOpts, client, signer, deadline, new(util.SystemTimeSource), mf)

	handlers := logCtx.Handlers(cfg.Prefix)
	return &handlers, nil
}
