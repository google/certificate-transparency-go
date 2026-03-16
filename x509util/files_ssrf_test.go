package x509util

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestRejectPrivateHost(t *testing.T) {
	tests := []struct {
		url     string
		wantErr bool
	}{
		{"http://169.254.169.254/latest/meta-data/", true},
		{"http://127.0.0.1/secret", true},
		{"http://192.168.1.1/admin", true},
		{"http://10.0.0.1/internal", true},
		{"http://[::1]/secret", true},
		{"http://localhost/secret", true},
		{"http://example.com/public", false},
		{"http://8.8.8.8/dns", false},
	}

	for _, tt := range tests {
		u, _ := url.Parse(tt.url)
		err := rejectPrivateHost(u)
		if (err != nil) != tt.wantErr {
			t.Errorf("rejectPrivateHost(%q) error=%v wantErr=%v",
				tt.url, err, tt.wantErr)
		}
	}
}

func TestReadFileOrURL_SSRFBypass(t *testing.T) {
	srv := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("SECRET_INTERNAL_DATA"))
		}))
	defer srv.Close()

	client := &http.Client{}
	localhostURL := "http://localhost:" + 
		srv.Listener.Addr().String()[len("127.0.0.1:"):]  + "/secret"

	_, err := ReadFileOrURL(localhostURL, client)
	if err == nil {
		t.Errorf("ReadFileOrURL should reject localhost URL: %s", localhostURL)
	}
}

func TestReadFileOrURL_PublicURL(t *testing.T) {
	client := &http.Client{}
	_, err := ReadFileOrURL("https://example.com/", client)
	if err != nil {
		t.Skipf("network unavailable: %v", err)
	}
}
