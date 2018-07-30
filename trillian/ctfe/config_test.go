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

package ctfe

import (
	"strings"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/any"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/google/certificate-transparency-go/trillian/ctfe/configpb"
	"github.com/google/certificate-transparency-go/trillian/ctfe/testonly"
	kto "github.com/google/trillian/crypto/keys/testonly"
	"github.com/google/trillian/crypto/keyspb"
)

var (
	pubKey = &keyspb.PublicKey{
		Der: kto.MustMarshalPublicPEMToDER(testonly.CTLogPublicKeyPEM),
	}
	// Note: Any non-nil private key verifies as correct because private key spec
	// is implementation specific. It needs to be verified additionally.
	privKey          = &any.Any{}
	invalidTimestamp = &timestamp.Timestamp{Nanos: int32(1e9)}
)

func TestValidateLogConfig(t *testing.T) {
	for _, tc := range []struct {
		desc    string
		cfg     configpb.LogConfig
		wantErr string
	}{
		{
			desc:    "empty-log-ID",
			wantErr: "empty log ID",
			cfg:     configpb.LogConfig{},
		},
		{
			desc:    "empty-private-key",
			wantErr: "empty private key",
			cfg:     configpb.LogConfig{LogId: 123},
		},
		{
			desc:    "empty-public-key",
			wantErr: "empty public key",
			cfg:     configpb.LogConfig{LogId: 123, IsMirror: true},
		},
		{
			desc:    "invalid-public-key-empty",
			wantErr: "invalid public key",
			cfg: configpb.LogConfig{
				LogId:     123,
				PublicKey: &keyspb.PublicKey{},
				IsMirror:  true,
			},
		},
		{
			desc:    "invalid-public-key-abacaba",
			wantErr: "invalid public key",
			cfg: configpb.LogConfig{
				LogId:     123,
				PublicKey: &keyspb.PublicKey{Der: []byte("abacaba")},
				IsMirror:  true,
			},
		},
		{
			desc:    "invalid-start-timestamp",
			wantErr: "invalid start timestamp",
			cfg: configpb.LogConfig{
				LogId:         123,
				PrivateKey:    privKey,
				NotAfterStart: invalidTimestamp,
			},
		},
		{
			desc:    "invalid-limit-timestamp",
			wantErr: "invalid limit timestamp",
			cfg: configpb.LogConfig{
				LogId:         123,
				PrivateKey:    privKey,
				NotAfterLimit: invalidTimestamp,
			},
		},
		{
			desc:    "limit-before-start",
			wantErr: "limit before start",
			cfg: configpb.LogConfig{
				LogId:         123,
				PrivateKey:    privKey,
				NotAfterStart: &timestamp.Timestamp{Seconds: 200},
				NotAfterLimit: &timestamp.Timestamp{Seconds: 100},
			},
		},
		{
			desc: "ok",
			cfg: configpb.LogConfig{
				LogId:      123,
				PrivateKey: privKey,
			},
		},
		{
			desc: "ok-mirror",
			cfg: configpb.LogConfig{
				LogId:     123,
				PublicKey: pubKey,
				IsMirror:  true,
			},
		},
		{
			desc: "ok-start-timestamp",
			cfg: configpb.LogConfig{
				LogId:         123,
				PrivateKey:    privKey,
				NotAfterStart: &timestamp.Timestamp{Seconds: 100},
			},
		},
		{
			desc: "ok-limit-timestamp",
			cfg: configpb.LogConfig{
				LogId:         123,
				PrivateKey:    privKey,
				NotAfterLimit: &timestamp.Timestamp{Seconds: 200},
			},
		},
		{
			desc: "ok-range-timestamp",
			cfg: configpb.LogConfig{
				LogId:         123,
				PrivateKey:    privKey,
				NotAfterStart: &timestamp.Timestamp{Seconds: 300},
				NotAfterLimit: &timestamp.Timestamp{Seconds: 400},
			},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			err := ValidateLogConfig(&tc.cfg)
			if len(tc.wantErr) == 0 && err != nil {
				t.Errorf("ValidateLogConfig(): %v", err)
			}
			if len(tc.wantErr) > 0 && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Errorf("ValidateLogConfig() returned %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestValidateLogMultiConfig(t *testing.T) {
	for _, tc := range []struct {
		desc    string
		cfg     configpb.LogMultiConfig
		wantErr string
	}{
		{
			desc:    "empty-backend-name",
			wantErr: "empty backend name",
			cfg: configpb.LogMultiConfig{
				Backends: &configpb.LogBackendSet{
					Backend: []*configpb.LogBackend{
						{BackendSpec: "testspec"},
					},
				},
			},
		},
		{
			desc:    "empty-backend-spec",
			wantErr: "empty backend spec",
			cfg: configpb.LogMultiConfig{
				Backends: &configpb.LogBackendSet{
					Backend: []*configpb.LogBackend{
						{Name: "log1"},
					},
				},
			},
		},
		{
			desc:    "duplicate-backend-name",
			wantErr: "duplicate backend name",
			cfg: configpb.LogMultiConfig{
				Backends: &configpb.LogBackendSet{
					Backend: []*configpb.LogBackend{
						{Name: "dup", BackendSpec: "testspec"},
						{Name: "dup", BackendSpec: "testspec"},
					},
				},
			},
		},
		{
			desc:    "duplicate-backend-spec",
			wantErr: "duplicate backend spec",
			cfg: configpb.LogMultiConfig{
				Backends: &configpb.LogBackendSet{
					Backend: []*configpb.LogBackend{
						{Name: "log1", BackendSpec: "testspec"},
						{Name: "log2", BackendSpec: "testspec"},
					},
				},
			},
		},
		{
			desc:    "invalid-log-config",
			wantErr: "log config: empty log ID",
			cfg: configpb.LogMultiConfig{
				Backends: &configpb.LogBackendSet{
					Backend: []*configpb.LogBackend{
						{Name: "log1", BackendSpec: "testspec"},
					},
				},
				LogConfigs: &configpb.LogConfigSet{
					Config: []*configpb.LogConfig{
						{},
					},
				},
			},
		},
		{
			desc:    "empty-prefix",
			wantErr: "empty prefix",
			cfg: configpb.LogMultiConfig{
				Backends: &configpb.LogBackendSet{
					Backend: []*configpb.LogBackend{
						{Name: "log1", BackendSpec: "testspec"},
					},
				},
				LogConfigs: &configpb.LogConfigSet{
					Config: []*configpb.LogConfig{
						{LogId: 1, PrivateKey: privKey, LogBackendName: "log1"},
					},
				},
			},
		},
		{
			desc:    "duplicate-prefix",
			wantErr: "duplicate prefix",
			cfg: configpb.LogMultiConfig{
				Backends: &configpb.LogBackendSet{
					Backend: []*configpb.LogBackend{
						{Name: "log1", BackendSpec: "testspec1"},
					},
				},
				LogConfigs: &configpb.LogConfigSet{
					Config: []*configpb.LogConfig{
						{LogId: 1, Prefix: "pref1", PrivateKey: privKey, LogBackendName: "log1"},
						{LogId: 2, Prefix: "pref2", PrivateKey: privKey, LogBackendName: "log1"},
						{LogId: 3, Prefix: "pref1", PrivateKey: privKey, LogBackendName: "log1"},
					},
				},
			},
		},
		{
			desc:    "references-undefined-backend",
			wantErr: "references undefined backend",
			cfg: configpb.LogMultiConfig{
				Backends: &configpb.LogBackendSet{
					Backend: []*configpb.LogBackend{
						{Name: "log1", BackendSpec: "testspec"},
					},
				},
				LogConfigs: &configpb.LogConfigSet{
					Config: []*configpb.LogConfig{
						{LogId: 2, Prefix: "pref2", PrivateKey: privKey, LogBackendName: "log2"},
					},
				},
			},
		},
		{
			desc:    "dup-tree-id-on-same-backend",
			wantErr: "dup tree id",
			cfg: configpb.LogMultiConfig{
				Backends: &configpb.LogBackendSet{
					Backend: []*configpb.LogBackend{
						{Name: "log1", BackendSpec: "testspec1"},
					},
				},
				LogConfigs: &configpb.LogConfigSet{
					Config: []*configpb.LogConfig{
						{LogId: 1, Prefix: "pref1", PrivateKey: privKey, LogBackendName: "log1"},
						{LogId: 2, Prefix: "pref2", PrivateKey: privKey, LogBackendName: "log1"},
						{LogId: 1, Prefix: "pref3", PrivateKey: privKey, LogBackendName: "log1"},
					},
				},
			},
		},
		{
			desc: "ok-all-distinct",
			cfg: configpb.LogMultiConfig{
				Backends: &configpb.LogBackendSet{
					Backend: []*configpb.LogBackend{
						{Name: "log1", BackendSpec: "testspec1"},
						{Name: "log2", BackendSpec: "testspec2"},
						{Name: "log3", BackendSpec: "testspec3"},
					},
				},
				LogConfigs: &configpb.LogConfigSet{
					Config: []*configpb.LogConfig{
						{LogId: 1, Prefix: "pref1", PrivateKey: privKey, LogBackendName: "log1"},
						{LogId: 2, Prefix: "pref2", PrivateKey: privKey, LogBackendName: "log2"},
						{LogId: 3, Prefix: "pref3", PrivateKey: privKey, LogBackendName: "log3"},
					},
				},
			},
		},
		{
			desc: "ok-dup-tree-ids-on-different-backends",
			cfg: configpb.LogMultiConfig{
				Backends: &configpb.LogBackendSet{
					Backend: []*configpb.LogBackend{
						{Name: "log1", BackendSpec: "testspec1"},
						{Name: "log2", BackendSpec: "testspec2"},
						{Name: "log3", BackendSpec: "testspec3"},
					},
				},
				LogConfigs: &configpb.LogConfigSet{
					Config: []*configpb.LogConfig{
						{LogId: 1, Prefix: "pref1", PrivateKey: privKey, LogBackendName: "log1"},
						{LogId: 1, Prefix: "pref2", PrivateKey: privKey, LogBackendName: "log2"},
						{LogId: 1, Prefix: "pref3", PrivateKey: privKey, LogBackendName: "log3"},
					},
				},
			},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			_, err := ValidateLogMultiConfig(&tc.cfg)
			if len(tc.wantErr) == 0 && err != nil {
				t.Fatalf("ValidateLogMultiConfig()=%v, want: nil", err)
			}
			if len(tc.wantErr) > 0 && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Errorf("ValidateLogMultiConfig()=%v, want: %v", err, tc.wantErr)
			}
		})
	}
}

func TestToMultiLogConfig(t *testing.T) {
	const defaultSpec = "spec"

	for _, tc := range []struct {
		desc string
		cfg  []*configpb.LogConfig
		want *configpb.LogMultiConfig
	}{
		{
			desc: "ok-one-config",
			cfg: []*configpb.LogConfig{
				{LogId: 1, Prefix: "pref1"},
			},
			want: &configpb.LogMultiConfig{
				Backends: &configpb.LogBackendSet{
					Backend: []*configpb.LogBackend{{Name: "default", BackendSpec: defaultSpec}},
				},
				LogConfigs: &configpb.LogConfigSet{
					Config: []*configpb.LogConfig{
						{LogId: 1, Prefix: "pref1", LogBackendName: "default"},
					},
				},
			},
		},
		{
			desc: "ok-three-configs",
			cfg: []*configpb.LogConfig{
				{LogId: 1, Prefix: "pref1"},
				{LogId: 2, Prefix: "pref2"},
				{LogId: 3, Prefix: "pref3"},
			},
			want: &configpb.LogMultiConfig{
				Backends: &configpb.LogBackendSet{
					Backend: []*configpb.LogBackend{{Name: "default", BackendSpec: defaultSpec}},
				},
				LogConfigs: &configpb.LogConfigSet{
					Config: []*configpb.LogConfig{
						{LogId: 1, Prefix: "pref1", LogBackendName: "default"},
						{LogId: 2, Prefix: "pref2", LogBackendName: "default"},
						{LogId: 3, Prefix: "pref3", LogBackendName: "default"},
					},
				},
			},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			got := ToMultiLogConfig(tc.cfg, defaultSpec)
			if !proto.Equal(got, tc.want) {
				t.Errorf("TestToMultiLogConfig() got: %v, want: %v", got, tc.want)
			}
		})
	}
}
