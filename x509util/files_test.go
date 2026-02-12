// Copyright 2026 Google LLC. All Rights Reserved.
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

package x509util

import (
	"net/url"
	"testing"
)

func TestRejectPrivateHost(t *testing.T) {
	tests := []struct {
		name    string
		rawURL  string
		wantErr bool
	}{
		{name: "loopback_v4", rawURL: "http://127.0.0.1/foo", wantErr: true},
		{name: "loopback_v6", rawURL: "http://[::1]/foo", wantErr: true},
		{name: "link_local_v4", rawURL: "http://169.254.1.1/foo", wantErr: true},
		{name: "private_10", rawURL: "http://10.0.0.1/foo", wantErr: true},
		{name: "private_172", rawURL: "http://172.16.0.1/foo", wantErr: true},
		{name: "private_192", rawURL: "http://192.168.1.1/foo", wantErr: true},
		{name: "public_ip", rawURL: "http://8.8.8.8/foo", wantErr: false},
		{name: "public_hostname", rawURL: "https://example.com/issuer.der", wantErr: false},
		{name: "aws_imds", rawURL: "http://169.254.169.254/latest/meta-data/", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.rawURL)
			if err != nil {
				t.Fatalf("url.Parse(%q) failed: %v", tt.rawURL, err)
			}
			err = rejectPrivateHost(u)
			if (err != nil) != tt.wantErr {
				t.Errorf("rejectPrivateHost(%q) error = %v, wantErr = %v", tt.rawURL, err, tt.wantErr)
			}
		})
	}
}
