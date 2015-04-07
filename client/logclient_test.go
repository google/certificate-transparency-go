package client

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
)

const (
	ValidSTHResponse = `{"tree_size":3721782,"timestamp":1396609800587,
        "sha256_root_hash":"SxKOxksguvHPyUaKYKXoZHzXl91Q257+JQ0AUMlFfeo=",
        "tree_head_signature":"BAMARjBEAiBUYO2tODlUUw4oWGiVPUHqZadRRyXs9T2rSXchA79VsQIgLASkQv3cu4XdPFCZbgFkIUefniNPCpO3LzzHX53l+wg="}`
	ValidSTHResponse_TreeSize          = 3721782
	ValidSTHResponse_Timestamp         = 1396609800587
	ValidSTHResponse_SHA256RootHash    = "SxKOxksguvHPyUaKYKXoZHzXl91Q257+JQ0AUMlFfeo="
	ValidSTHResponse_TreeHeadSignature = "BAMARjBEAiBUYO2tODlUUw4oWGiVPUHqZadRRyXs9T2rSXchA79VsQIgLASkQv3cu4XdPFCZbgFkIUefniNPCpO3LzzHX53l+wg="
)

func TestGetEntriesWorks(t *testing.T) {
	positiveDecimalNumber := regexp.MustCompile("[0-9]+")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ct/v1/get-entries" {
			t.Fatalf("Incorrect URL path: %s", r.URL.Path)
		}
		q := r.URL.Query()
		if q["start"] == nil {
			t.Fatal("Missing 'start' parameter")
		}
		if !positiveDecimalNumber.MatchString(q["start"][0]) {
			t.Fatal("Invalid 'start' parameter: " + q["start"][0])
		}
		if q["end"] == nil {
			t.Fatal("Missing 'end' parameter")
		}
		if !positiveDecimalNumber.MatchString(q["end"][0]) {
			t.Fatal("Invalid 'end' parameter: " + q["end"][0])
		}
		fmt.Fprintf(w, `{"entries":[{"leaf_input": "%s","extra_data": "%s"},{"leaf_input": "%s","extra_data": "%s"}]}`, PrecertEntryB64, PrecertEntryExtraDataB64, CertEntryB64, CertEntryExtraDataB64)
	}))
	defer ts.Close()

	client := New(ts.URL)
	leaves, err := client.GetEntries(0, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(leaves) != 2 {
		t.Fatal("Incorrect number of leaves returned")
	}
}

func TestGetSTHWorks(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ct/v1/get-sth" {
			t.Fatalf("Incorrect URL path: %s", r.URL.Path)
		}
		fmt.Fprintf(w, `{"tree_size": %d, "timestamp": %d, "sha256_root_hash": "%s", "tree_head_signature": "%s"}`,
			ValidSTHResponse_TreeSize, int64(ValidSTHResponse_Timestamp), ValidSTHResponse_SHA256RootHash,
			ValidSTHResponse_TreeHeadSignature)
	}))
	defer ts.Close()

	client := New(ts.URL)
	sth, err := client.GetSTH()
	if err != nil {
		t.Fatal(err)
	}
	if sth.TreeSize != ValidSTHResponse_TreeSize {
		t.Fatal("Invalid tree size")
	}
	if sth.Timestamp != ValidSTHResponse_Timestamp {
		t.Fatal("Invalid Timestamp")
	}
	hash, err := base64.StdEncoding.DecodeString(ValidSTHResponse_SHA256RootHash)
	if err != nil {
		t.Fatal("Couldn't b64 decode 'correct' STH root hash!")
	}
	if string(sth.SHA256RootHash) != string(hash) {
		t.Fatal("Invalid SHA256RootHash")
	}
	sig, err := base64.StdEncoding.DecodeString(ValidSTHResponse_TreeHeadSignature)
	if err != nil {
		t.Fatal("Couldn't b64 decode 'correct' STH signature!")
	}
	if string(sth.TreeHeadSignature) != string(sig) {
		t.Fatal("Invalid TreeHeadSignature")
	}
}
