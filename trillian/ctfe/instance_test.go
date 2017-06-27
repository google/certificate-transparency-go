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
	"strings"
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/google/certificate-transparency-go/trillian/ctfe/configpb"
	"github.com/google/trillian/crypto/keys"
	"github.com/google/trillian/crypto/keyspb"
	"github.com/google/trillian/monitoring"
)

func TestSetUpInstance(t *testing.T) {
	ctx := context.Background()
	sf := &keys.DefaultSignerFactory{}

	privKey, err := ptypes.MarshalAny(&keyspb.PEMKeyFile{Path: "../testdata/ct-http-server.privkey.pem", Password: "dirk"})
	if err != nil {
		t.Fatalf("Could not marshal private key proto: %v", err)
	}

	missingPrivKey, err := ptypes.MarshalAny(&keyspb.PEMKeyFile{Path: "../testdata/bogus.privkey.pem", Password: "dirk"})
	if err != nil {
		t.Fatalf("Could not marshal private key proto: %v", err)
	}

	wrongPassPrivKey, err := ptypes.MarshalAny(&keyspb.PEMKeyFile{Path: "../testdata/ct-http-server.privkey.pem", Password: "dirkly"})
	if err != nil {
		t.Fatalf("Could not marshal private key proto: %v", err)
	}

	var tests = []struct {
		desc   string
		cfg    configpb.LogConfig
		errStr string
	}{
		{
			desc: "valid",
			cfg: configpb.LogConfig{
				LogId:        1,
				Prefix:       "log",
				RootsPemFile: []string{"../testdata/fake-ca.cert"},
				PrivateKey:   privKey,
			},
		},
		{
			desc: "no-roots",
			cfg: configpb.LogConfig{
				LogId:      1,
				Prefix:     "log",
				PrivateKey: privKey,
			},
			errStr: "specify RootsPemFile",
		},
		{
			desc: "no-priv-key",
			cfg: configpb.LogConfig{
				LogId:        1,
				Prefix:       "log",
				RootsPemFile: []string{"../testdata/fake-ca.cert"},
			},
			errStr: "specify PrivateKey",
		},
		{
			desc: "missing-root-cert",
			cfg: configpb.LogConfig{
				LogId:        1,
				Prefix:       "log",
				RootsPemFile: []string{"../testdata/bogus.cert"},
				PrivateKey:   privKey,
			},
			errStr: "failed to read trusted roots",
		},
		{
			desc: "missing-privkey",
			cfg: configpb.LogConfig{
				LogId:        1,
				Prefix:       "log",
				RootsPemFile: []string{"../testdata/fake-ca.cert"},
				PrivateKey:   missingPrivKey,
			},
			errStr: "failed to load private key",
		},
		{
			desc: "privkey-wrong-password",
			cfg: configpb.LogConfig{
				LogId:        1,
				Prefix:       "log",
				RootsPemFile: []string{"../testdata/fake-ca.cert"},
				PrivateKey:   wrongPassPrivKey,
			},
			errStr: "failed to load private key",
		},
		{
			desc: "valid-ekus-1",
			cfg: configpb.LogConfig{
				LogId:        1,
				Prefix:       "log",
				RootsPemFile: []string{"../testdata/fake-ca.cert"},
				PrivateKey:   privKey,
				ExtKeyUsages: []string{"Any"},
			},
		},
		{
			desc: "valid-ekus-2",
			cfg: configpb.LogConfig{
				LogId:        1,
				Prefix:       "log",
				RootsPemFile: []string{"../testdata/fake-ca.cert"},
				PrivateKey:   privKey,
				ExtKeyUsages: []string{"Any", "ServerAuth", "TimeStamping"},
			},
		},
		{
			desc: "invalid-ekus-1",
			cfg: configpb.LogConfig{
				LogId:        1,
				Prefix:       "log",
				RootsPemFile: []string{"../testdata/fake-ca.cert"},
				PrivateKey:   privKey,
				ExtKeyUsages: []string{"Any", "ServerAuth", "TimeStomping"},
			},
			errStr: "unknown extended key usage",
		},
		{
			desc: "invalid-ekus-2",
			cfg: configpb.LogConfig{
				LogId:        1,
				Prefix:       "log",
				RootsPemFile: []string{"../testdata/fake-ca.cert"},
				PrivateKey:   privKey,
				ExtKeyUsages: []string{"Any "},
			},
			errStr: "unknown extended key usage",
		},
	}

	for _, test := range tests {
		_, err := SetUpInstance(ctx, nil, &test.cfg, sf, time.Second, monitoring.InertMetricFactory{})
		if err != nil {
			if test.errStr == "" {
				t.Errorf("(%v).SetUpInstance()=_,%v; want _,nil", test.desc, err)
			} else if !strings.Contains(err.Error(), test.errStr) {
				t.Errorf("(%v).SetUpInstance()=_,%v; want err containing %q", test.desc, err, test.errStr)
			}
			continue
		}
		if test.errStr != "" {
			t.Errorf("(%v).SetUpInstance()=_,mo;; want err containing %q", test.desc, test.errStr)
		}
	}

}
