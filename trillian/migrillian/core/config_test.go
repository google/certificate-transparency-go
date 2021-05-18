// Copyright 2018 Google LLC. All Rights Reserved.
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

package core

import (
	"encoding/pem"
	"strings"
	"testing"

	"github.com/google/certificate-transparency-go/trillian/ctfe/testonly"
	"github.com/google/certificate-transparency-go/trillian/migrillian/configpb"
	"github.com/google/trillian/crypto/keyspb"
)

const ctURI = "https://ct.googleapis.com/testtube"

func TestLoadConfigFromFileValid(t *testing.T) {
	for _, tc := range []struct {
		desc      string
		filename  string
		wantItems int
	}{
		{desc: "text proto", filename: "../testdata/config.textproto", wantItems: 2},
		{desc: "binary proto", filename: "../testdata/config.pb", wantItems: 1},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			cfg, err := LoadConfigFromFile(tc.filename)
			if err != nil {
				t.Fatalf("LoadConfigFromFile(): %v", err)
			}
			if cfg == nil {
				t.Fatal("Config is nil")
			}
			if err := ValidateConfig(cfg); err != nil {
				t.Fatalf("Loaded invalid config: %v", err)
			}
			if got, want := len(cfg.MigrationConfigs.Config), tc.wantItems; got != want {
				t.Errorf("Wrong number of migration configs %d, want %d", got, want)
			}
		})
	}
}

func TestLoadConfigFromFileErrors(t *testing.T) {
	for _, tc := range []struct {
		desc     string
		filename string
		wantErr  string
	}{
		{desc: "no-such-file", filename: "does-not-exist", wantErr: "no such file"},
		{desc: "wrong-format", filename: "../testdata/not-config.textproto", wantErr: "failed to parse"},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			cfg, err := LoadConfigFromFile(tc.filename)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("Expected error containing %q", tc.wantErr)
			}
			if cfg != nil {
				t.Error("Expected nil config")
			}
		})
	}
}

func TestValidateMigrationConfig(t *testing.T) {
	block, _ := pem.Decode([]byte(testonly.CTLogPublicKeyPEM))
	pubKey := &keyspb.PublicKey{Der: block.Bytes}

	for _, tc := range []struct {
		desc    string
		cfg     *configpb.MigrationConfig
		wantErr string
	}{
		{
			desc:    "missing-source-uri",
			cfg:     &configpb.MigrationConfig{},
			wantErr: "missing CT log URI",
		},
		{
			desc:    "missing-pub-key",
			cfg:     &configpb.MigrationConfig{SourceUri: ctURI},
			wantErr: "missing public key",
		},
		{
			desc:    "wrong-log-ID",
			cfg:     &configpb.MigrationConfig{SourceUri: ctURI, PublicKey: pubKey},
			wantErr: "log ID must be positive",
		},
		{
			desc: "wrong-batch-size",
			cfg: &configpb.MigrationConfig{SourceUri: ctURI, PublicKey: pubKey,
				LogId: 10},
			wantErr: "batch size must be positive",
		},
		{
			desc: "unknown-identity-function",
			cfg: &configpb.MigrationConfig{SourceUri: ctURI, PublicKey: pubKey,
				LogId: 10, BatchSize: 100},
			wantErr: "unknown identity function",
		},
		{
			desc: "ok",
			cfg: &configpb.MigrationConfig{SourceUri: ctURI, PublicKey: pubKey,
				LogId: 10, BatchSize: 100,
				IdentityFunction: configpb.IdentityFunction_SHA256_CERT_DATA},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			err := ValidateMigrationConfig(tc.cfg)
			if len(tc.wantErr) == 0 && err != nil {
				t.Errorf("ValidateMigrationConfig()=%v, want nil", err)
			}
			if len(tc.wantErr) > 0 && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Errorf("ValidateMigrationConfig()=%v, want err containing %q", err, tc.wantErr)
			}
		})
	}
}
