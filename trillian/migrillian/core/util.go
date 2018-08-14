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
	"crypto/sha256"
	"errors"
	"fmt"
	"io/ioutil"

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/trillian/migrillian/configpb"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/trillian"
)

// LoadConfigFromFile reads MigrationConfig from the given filename, which
// should contain text-protobuf encoded configuration data.
func LoadConfigFromFile(filename string) (*configpb.MigrationConfig, error) {
	text, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var cfg configpb.MigrationConfig
	if err := proto.UnmarshalText(string(text), &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse log config: %v", err)
	}
	return &cfg, nil
}

// ValidateConfig verifies that the config is sane.
func ValidateConfig(cfg *configpb.MigrationConfig) error {
	switch {
	case len(cfg.SourceUri) == 0:
		return errors.New("missing CT log URI")
	case cfg.PublicKey == nil:
		return errors.New("missing public key")
	case len(cfg.TrillianUri) == 0:
		return errors.New("missing Trillian URI")
	case cfg.LogId <= 0:
		return errors.New("log ID must be positive")
	case cfg.BatchSize <= 0:
		return errors.New("batch size must be positive")
	}
	return nil
}

func buildLogLeaf(logPrefix string, index int64, entry *ct.LeafEntry) (*trillian.LogLeaf, error) {
	rle, err := ct.RawLogEntryFromLeaf(index, entry)
	if err != nil {
		return nil, err
	}

	// Don't return on x509 parsing errors because we want to migrate this log
	// entry as is. But log the error so that it can be flagged by monitoring.
	if _, err = rle.ToLogEntry(); x509.IsFatal(err) {
		glog.Errorf("%s: index=%d: x509 fatal error: %v", logPrefix, index, err)
	} else if err != nil {
		glog.Infof("%s: index=%d: x509 non-fatal error: %v", logPrefix, index, err)
	}
	// TODO(pavelkalinnikov): Verify cert chain if error is nil or non-fatal.

	leafIDHash := sha256.Sum256(rle.Cert.Data)
	return &trillian.LogLeaf{
		LeafValue:        entry.LeafInput,
		ExtraData:        entry.ExtraData,
		LeafIndex:        index,
		LeafIdentityHash: leafIDHash[:],
	}, nil
}
