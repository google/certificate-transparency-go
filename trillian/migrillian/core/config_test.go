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

package core

import (
	"strings"
	"testing"

	"github.com/google/certificate-transparency-go/trillian/ctfe/testonly"
	"github.com/google/certificate-transparency-go/trillian/migrillian/configpb"
	kto "github.com/google/trillian/crypto/keys/testonly"
	"github.com/google/trillian/crypto/keyspb"
)

func TestValidateConfig(t *testing.T) {
	const ctURI = "https://example.com/loggymclogface"
	const back = "trillian.example.com:8090"
	pubKey := &keyspb.PublicKey{
		Der: kto.MustMarshalPublicPEMToDER(testonly.CTLogPublicKeyPEM),
	}

	for _, tc := range []struct {
		desc    string
		cfg     configpb.MigrationConfig
		wantErr string
	}{
		{
			desc:    "missing-source-uri",
			cfg:     configpb.MigrationConfig{},
			wantErr: "missing CT log URI",
		},
		{
			desc:    "missing-pub-key",
			cfg:     configpb.MigrationConfig{SourceUri: ctURI},
			wantErr: "missing public key",
		},
		{
			desc:    "missing-backend",
			cfg:     configpb.MigrationConfig{SourceUri: ctURI, PublicKey: pubKey},
			wantErr: "missing Trillian URI",
		},
		{
			desc:    "wrong-log-ID",
			cfg:     configpb.MigrationConfig{SourceUri: ctURI, PublicKey: pubKey, TrillianUri: back},
			wantErr: "log ID must be positive",
		},
		{
			desc: "wrong-batch-size",
			cfg: configpb.MigrationConfig{SourceUri: ctURI, PublicKey: pubKey,
				TrillianUri: back, LogId: 10},
			wantErr: "batch size must be positive",
		},
		{
			desc: "ok",
			cfg: configpb.MigrationConfig{SourceUri: ctURI, PublicKey: pubKey,
				TrillianUri: back, LogId: 10, BatchSize: 100},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			err := ValidateConfig(&tc.cfg)
			if len(tc.wantErr) == 0 && err != nil {
				t.Errorf("ValidateConfig()=%v, want nil", err)
			}
			if len(tc.wantErr) > 0 && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Errorf("ValidateConfig()=%v, want err containing %q", err, tc.wantErr)
			}
		})
	}
}
