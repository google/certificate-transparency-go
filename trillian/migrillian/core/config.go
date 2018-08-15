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
	"errors"
	"fmt"
	"io/ioutil"

	"github.com/golang/protobuf/proto"
	"github.com/google/certificate-transparency-go/trillian/migrillian/configpb"
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
	case len(cfg.LogBackendName) == 0:
		return errors.New("missing log backend name")
	case cfg.LogId <= 0:
		return errors.New("log ID must be positive")
	case cfg.BatchSize <= 0:
		return errors.New("batch size must be positive")
	}
	return nil
}
