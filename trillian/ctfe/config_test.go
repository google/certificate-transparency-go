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
	"strings"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/google/certificate-transparency-go/trillian/ctfe/configpb"
)

func TestValidateLogMultiConfig(t *testing.T) {
	var tests = []struct {
		desc    string
		cfg     configpb.LogMultiConfig
		wantErr string
	}{
		{
			desc:    "missing-backend-name",
			wantErr: "empty backend name",
			cfg: configpb.LogMultiConfig{
				Backends: &configpb.LogBackendSet{
					Backend: []*configpb.LogBackend{
						{BackendSpec: "testspec"},
					},
				},
				LogConfigs: &configpb.LogConfigSet{},
			},
		},
		{
			desc:    "missing-backend-spec",
			wantErr: "empty backend_spec",
			cfg: configpb.LogMultiConfig{
				Backends: &configpb.LogBackendSet{
					Backend: []*configpb.LogBackend{
						{Name: "log1"},
					},
				},
				LogConfigs: &configpb.LogConfigSet{},
			},
		},
		{
			desc:    "missing-backend-name-and-spec",
			wantErr: "empty backend name",
			cfg: configpb.LogMultiConfig{
				Backends: &configpb.LogBackendSet{
					Backend: []*configpb.LogBackend{
						{},
					},
				},
				LogConfigs: &configpb.LogConfigSet{},
			},
		},
		{
			desc:    "dup-backend-name",
			wantErr: "duplicate backend name",
			cfg: configpb.LogMultiConfig{
				Backends: &configpb.LogBackendSet{
					Backend: []*configpb.LogBackend{
						{Name: "dup", BackendSpec: "testspec"},
						{Name: "dup", BackendSpec: "testspec"},
					},
				},
				LogConfigs: &configpb.LogConfigSet{},
			},
		},
		{
			desc:    "dup-backend-spec",
			wantErr: "duplicate backend spec",
			cfg: configpb.LogMultiConfig{
				Backends: &configpb.LogBackendSet{
					Backend: []*configpb.LogBackend{
						{Name: "backend1", BackendSpec: "testspec"},
						{Name: "backend2", BackendSpec: "testspec"},
					},
				},
				LogConfigs: &configpb.LogConfigSet{},
			},
		},
		{
			desc:    "missing-backend-reference",
			wantErr: "empty backend",
			cfg: configpb.LogMultiConfig{
				Backends: &configpb.LogBackendSet{
					Backend: []*configpb.LogBackend{
						{Name: "log1"},
					},
				},
				LogConfigs: &configpb.LogConfigSet{
					Config: []*configpb.LogConfig{
						{LogBackendName: "log2"},
					},
				},
			},
		},
		{
			desc:    "undefined-backend-reference",
			wantErr: "undefined backend",
			cfg: configpb.LogMultiConfig{
				Backends: &configpb.LogBackendSet{
					Backend: []*configpb.LogBackend{
						{Name: "log1", BackendSpec: "testspec"},
					},
				},
				LogConfigs: &configpb.LogConfigSet{
					Config: []*configpb.LogConfig{
						{LogBackendName: "log2", Prefix: "prefix"},
					},
				},
			},
		},
		{
			desc:    "empty-log-prefix",
			wantErr: "empty prefix",
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
						{LogBackendName: "log1", Prefix: "prefix1"},
						{LogBackendName: "log2"},
						{LogBackendName: "log3", Prefix: "prefix3"},
					},
				},
			},
		},
		{
			desc:    "dup-log-prefix",
			wantErr: "duplicate prefix",
			cfg: configpb.LogMultiConfig{
				Backends: &configpb.LogBackendSet{
					Backend: []*configpb.LogBackend{
						{Name: "log1", BackendSpec: "testspec1"},
					},
				},
				LogConfigs: &configpb.LogConfigSet{
					Config: []*configpb.LogConfig{
						{LogBackendName: "log1", Prefix: "prefix1", LogId: 1},
						{LogBackendName: "log1", Prefix: "prefix2", LogId: 2},
						{LogBackendName: "log1", Prefix: "prefix1", LogId: 3},
					},
				},
			},
		},
		{
			desc:    "dup-log-ids-on-same-backend",
			wantErr: "dup tree id",
			cfg: configpb.LogMultiConfig{
				Backends: &configpb.LogBackendSet{
					Backend: []*configpb.LogBackend{
						{Name: "log1", BackendSpec: "testspec1"},
					},
				},
				LogConfigs: &configpb.LogConfigSet{
					Config: []*configpb.LogConfig{
						{LogBackendName: "log1", Prefix: "prefix1", LogId: 1},
						{LogBackendName: "log1", Prefix: "prefix2", LogId: 1},
						{LogBackendName: "log1", Prefix: "prefix1", LogId: 1},
					},
				},
			},
		},
		{
			desc:    "start-timestamp-invalid",
			wantErr: "invalid start",
			cfg: configpb.LogMultiConfig{
				Backends: &configpb.LogBackendSet{
					Backend: []*configpb.LogBackend{
						{Name: "log1", BackendSpec: "testspec1"},
					},
				},
				LogConfigs: &configpb.LogConfigSet{
					Config: []*configpb.LogConfig{
						{
							LogBackendName: "log1",
							Prefix:         "prefix1",
							LogId:          1,
							NotAfterStart:  &timestamp.Timestamp{Seconds: 23, Nanos: -50},
							NotAfterLimit:  &timestamp.Timestamp{Seconds: 23},
						},
					},
				},
			},
		},
		{
			desc:    "limit-timestamp-invalid",
			wantErr: "invalid limit",
			cfg: configpb.LogMultiConfig{
				Backends: &configpb.LogBackendSet{
					Backend: []*configpb.LogBackend{
						{Name: "log1", BackendSpec: "testspec1"},
					},
				},
				LogConfigs: &configpb.LogConfigSet{
					Config: []*configpb.LogConfig{
						{
							LogBackendName: "log1",
							Prefix:         "prefix1",
							LogId:          1,
							NotAfterStart:  &timestamp.Timestamp{Seconds: 23},
							NotAfterLimit:  &timestamp.Timestamp{Seconds: 23, Nanos: -50},
						},
					},
				},
			},
		},
		{
			desc:    "limit-before-start",
			wantErr: "before start",
			cfg: configpb.LogMultiConfig{
				Backends: &configpb.LogBackendSet{
					Backend: []*configpb.LogBackend{
						{Name: "log1", BackendSpec: "testspec1"},
					},
				},
				LogConfigs: &configpb.LogConfigSet{
					Config: []*configpb.LogConfig{
						{
							LogBackendName: "log1",
							Prefix:         "prefix1",
							LogId:          1,
							NotAfterStart:  &timestamp.Timestamp{Seconds: 23},
							NotAfterLimit:  &timestamp.Timestamp{Seconds: 22},
						},
					},
				},
			},
		},
		{
			desc: "valid0config",
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
						{LogBackendName: "log1", Prefix: "prefix1", LogId: 1},
						{LogBackendName: "log2", Prefix: "prefix2", LogId: 2},
						{LogBackendName: "log3", Prefix: "prefix3", LogId: 3},
					},
				},
			},
		},
		{
			desc: "valid-config-dup-ids-on-different-backends",
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
						{LogBackendName: "log1", Prefix: "prefix1", LogId: 999},
						{LogBackendName: "log2", Prefix: "prefix2", LogId: 999},
						{LogBackendName: "log3", Prefix: "prefix3", LogId: 999},
					},
				},
			},
		},
		{
			desc: "valid-config-only-not-after-start-set",
			cfg: configpb.LogMultiConfig{
				Backends: &configpb.LogBackendSet{
					Backend: []*configpb.LogBackend{
						{Name: "log1", BackendSpec: "testspec1"},
					},
				},
				LogConfigs: &configpb.LogConfigSet{
					Config: []*configpb.LogConfig{
						{LogBackendName: "log1", Prefix: "prefix1", LogId: 1, NotAfterStart: &timestamp.Timestamp{Seconds: 23}},
					},
				},
			},
		},
		{
			desc: "valid-config-only-not-after-limit-set",
			cfg: configpb.LogMultiConfig{
				Backends: &configpb.LogBackendSet{
					Backend: []*configpb.LogBackend{
						{Name: "log1", BackendSpec: "testspec1"},
					},
				},
				LogConfigs: &configpb.LogConfigSet{
					Config: []*configpb.LogConfig{
						{LogBackendName: "log1", Prefix: "prefix1", LogId: 1, NotAfterLimit: &timestamp.Timestamp{Seconds: 23}},
					},
				},
			},
		},
		{
			desc: "valid-config-with-time-range",
			cfg: configpb.LogMultiConfig{
				Backends: &configpb.LogBackendSet{
					Backend: []*configpb.LogBackend{
						{Name: "log1", BackendSpec: "testspec1"},
					},
				},
				LogConfigs: &configpb.LogConfigSet{
					Config: []*configpb.LogConfig{
						{
							LogBackendName: "log1",
							Prefix:         "prefix1",
							LogId:          1,
							NotAfterStart:  &timestamp.Timestamp{Seconds: 23},
							NotAfterLimit:  &timestamp.Timestamp{Seconds: 24},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			_, err := ValidateLogMultiConfig(&test.cfg)
			if len(test.wantErr) == 0 && err != nil {
				t.Fatalf("ValidateLogMultiConfig()=%v, want: nil", err)
			}

			if len(test.wantErr) > 0 && (err == nil || !strings.Contains(err.Error(), test.wantErr)) {
				t.Errorf("ValidateLogMultiConfig()=%v, want: %v", err, test.wantErr)
			}
		})
	}
}

func TestToMultiLogConfig(t *testing.T) {
	var tests = []struct {
		desc string
		cfg  []*configpb.LogConfig
		want *configpb.LogMultiConfig
	}{
		{
			desc: "one valid log config",
			cfg: []*configpb.LogConfig{
				{LogId: 1, Prefix: "test"},
			},
			want: &configpb.LogMultiConfig{
				Backends: &configpb.LogBackendSet{
					Backend: []*configpb.LogBackend{{Name: "default", BackendSpec: "spec"}},
				},
				LogConfigs: &configpb.LogConfigSet{
					Config: []*configpb.LogConfig{{Prefix: "test", LogId: 1, LogBackendName: "default"}},
				},
			},
		},
		{
			desc: "three valid log configs",
			cfg: []*configpb.LogConfig{
				{LogId: 1, Prefix: "test1"},
				{LogId: 2, Prefix: "test2"},
				{LogId: 3, Prefix: "test3"},
			},
			want: &configpb.LogMultiConfig{
				Backends: &configpb.LogBackendSet{
					Backend: []*configpb.LogBackend{{Name: "default", BackendSpec: "spec"}},
				},
				LogConfigs: &configpb.LogConfigSet{
					Config: []*configpb.LogConfig{
						{Prefix: "test1", LogId: 1, LogBackendName: "default"},
						{Prefix: "test2", LogId: 2, LogBackendName: "default"},
						{Prefix: "test3", LogId: 3, LogBackendName: "default"},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			got := ToMultiLogConfig(test.cfg, "spec")
			if !proto.Equal(got, test.want) {
				t.Errorf("TestToMultiLogConfig() got: %v, want: %v", got, test.want)
			}
		})
	}
}
