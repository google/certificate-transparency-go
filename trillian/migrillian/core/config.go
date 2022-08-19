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
	"errors"
	"fmt"
	"os"

	"github.com/google/certificate-transparency-go/trillian/migrillian/configpb"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
)

// LoadConfigFromFile reads MigrillianConfig from the given filename, which
// should contain text-protobuf encoded configuration data.
func LoadConfigFromFile(filename string) (*configpb.MigrillianConfig, error) {
	cfgBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var cfg configpb.MigrillianConfig
	if txtErr := prototext.Unmarshal(cfgBytes, &cfg); txtErr != nil {
		if binErr := proto.Unmarshal(cfgBytes, &cfg); binErr != nil {
			return nil, fmt.Errorf("failed to parse MigrillianConfig from %q as text protobuf (%v) or binary protobuf (%v)", filename, txtErr, binErr)
		}
	}

	return &cfg, nil
}

// ValidateMigrationConfig verifies that the migration config is sane.
func ValidateMigrationConfig(cfg *configpb.MigrationConfig) error {
	// TODO(pavelkalinnikov): Also try to parse the public key.
	switch {
	case len(cfg.SourceUri) == 0:
		return errors.New("missing CT log URI")
	case cfg.PublicKey == nil:
		return errors.New("missing public key")
	case cfg.LogId <= 0:
		return errors.New("log ID must be positive")
	case cfg.BatchSize <= 0:
		return errors.New("batch size must be positive")
	}
	switch idFunc := cfg.IdentityFunction; idFunc {
	case configpb.IdentityFunction_SHA256_CERT_DATA:
	case configpb.IdentityFunction_SHA256_LEAF_INDEX:
	default:
		return fmt.Errorf("unknown identity function: %v", idFunc)
	}
	return nil
}

// ValidateConfig verifies that MigrillianConfig is correct. In particular:
// - Migration configs are valid (as per ValidateMigrationConfig).
// - Each migration config has a unique log ID.
func ValidateConfig(cfg *configpb.MigrillianConfig) error {
	// Validate each MigrationConfig, and ensure that log IDs are unique.
	logIDs := make(map[int64]bool)
	for _, mc := range cfg.MigrationConfigs.Config {
		if err := ValidateMigrationConfig(mc); err != nil {
			return fmt.Errorf("MigrationConfig: %v: %v", err, mc)
		}
		if ok := logIDs[mc.LogId]; ok {
			return fmt.Errorf("duplicate tree ID %d: %v", mc.LogId, mc)
		}
		logIDs[mc.LogId] = true
	}
	return nil
}
