package submission

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleAddSomeChainRejectsOversizedBody(t *testing.T) {
	s := &ProxyServer{}

	body := bytes.Repeat([]byte{0x41}, int(maxAddChainBodyBytes)+1)
	req := httptest.NewRequest(http.MethodPost, "http://example/ct/v1/proxy/add-chain", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	s.handleAddSomeChain(rr, req, false)

	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d, want %d", rr.Code, http.StatusRequestEntityTooLarge)
	}
}

func TestHandleAddSomeChainBadRequestUnderLimit(t *testing.T) {
	s := &ProxyServer{}

	body := bytes.Repeat([]byte{0x41}, 64)
	req := httptest.NewRequest(http.MethodPost, "http://example/ct/v1/proxy/add-chain", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	s.handleAddSomeChain(rr, req, false)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want %d", rr.Code, http.StatusBadRequest)
	}
}
