package http

import (
	"bytes"
	nethttp "net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
)

func TestUpdateRejectsOversizedBody(t *testing.T) {
	s := &Server{}

	body := bytes.Repeat([]byte{0x41}, int(maxUpdateRequestBodyBytes)+1)
	req := httptest.NewRequest(nethttp.MethodPut, "http://example/witness/v0/logs/logid/update", bytes.NewReader(body))
	req = mux.SetURLVars(req, map[string]string{"logid": "logid"})
	rr := httptest.NewRecorder()

	s.update(rr, req)

	if rr.Code != nethttp.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d, want %d", rr.Code, nethttp.StatusRequestEntityTooLarge)
	}
}

func TestUpdateBadRequestUnderLimit(t *testing.T) {
	s := &Server{}

	body := bytes.Repeat([]byte{0x41}, 64)
	req := httptest.NewRequest(nethttp.MethodPut, "http://example/witness/v0/logs/logid/update", bytes.NewReader(body))
	req = mux.SetURLVars(req, map[string]string{"logid": "logid"})
	rr := httptest.NewRecorder()

	s.update(rr, req)

	if rr.Code != nethttp.StatusBadRequest {
		t.Fatalf("status=%d, want %d", rr.Code, nethttp.StatusBadRequest)
	}
}
