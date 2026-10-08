package main

import "testing"

func TestIsLocalBackendSpec(t *testing.T) {
	tests := []struct {
		name string
		spec string
		want bool
	}{
		{name: "localhost", spec: "localhost:8090", want: true},
		{name: "ipv4_loopback", spec: "127.0.0.1:8090", want: true},
		{name: "ipv6_loopback", spec: "[::1]:8090", want: true},
		{name: "dns_scheme_localhost", spec: "dns:///localhost:8090", want: true},
		{name: "passthrough_scheme_loopback", spec: "passthrough:///127.0.0.1:8090", want: true},
		{name: "unix_scheme", spec: "unix:///tmp/trillian.sock", want: true},
		{name: "unix_prefix", spec: "unix:/tmp/trillian.sock", want: true},
		{name: "private_ipv4", spec: "10.0.0.1:8090", want: false},
		{name: "public_hostname", spec: "trillian.example:8090", want: false},
		{name: "passthrough_scheme_remote", spec: "passthrough:///10.0.0.1:8090", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isLocalBackendSpec(tt.spec); got != tt.want {
				t.Fatalf("isLocalBackendSpec(%q)=%v, want %v", tt.spec, got, tt.want)
			}
		})
	}
}

func TestTrillianBackendDialOption_PlaintextPolicy(t *testing.T) {
	t.Run("reject_non_local_without_tls_or_flag", func(t *testing.T) {
		_, _, err := trillianBackendDialOption("", false, []string{"10.0.0.1:8090"})
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
	})

	t.Run("allow_local_without_tls_or_flag", func(t *testing.T) {
		_, mode, err := trillianBackendDialOption("", false, []string{"localhost:8090"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if mode != trillianTransportPlaintextLocal {
			t.Fatalf("mode=%q, want %q", mode, trillianTransportPlaintextLocal)
		}
	})

	t.Run("allow_flag_without_tls", func(t *testing.T) {
		_, mode, err := trillianBackendDialOption("", true, []string{"10.0.0.1:8090"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if mode != trillianTransportPlaintextFlag {
			t.Fatalf("mode=%q, want %q", mode, trillianTransportPlaintextFlag)
		}
	})
}

