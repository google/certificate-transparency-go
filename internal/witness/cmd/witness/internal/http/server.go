// Copyright 2021 Google LLC. All Rights Reserved.
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

// Package http contains private implementation details for the witness server.
package http

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/google/certificate-transparency-go/internal/witness/api"
	"github.com/google/certificate-transparency-go/internal/witness/cmd/witness/internal/witness"
	"github.com/gorilla/mux"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Server is the core handler implementation of the witness.
type Server struct {
	w *witness.Witness
}

// NewServer creates a new server.
func NewServer(witness *witness.Witness) *Server {
	return &Server{
		w: witness,
	}
}

// update handles requests to update STHs.
// It expects a PUT body containing a JSON-formatted api.UpdateRequest
// statement and returns a JSON-formatted api.UpdateResponse statement.
func (s *Server) update(w http.ResponseWriter, r *http.Request) {
	v := mux.Vars(r)
	logID, err := url.PathUnescape(v["logid"])
	if err != nil {
		http.Error(w, fmt.Sprintf("cannot parse URL: %v", err.Error()), http.StatusBadRequest)
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("cannot read request body: %v", err.Error()), http.StatusBadRequest)
		return
	}
	var req api.UpdateRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, fmt.Sprintf("cannot parse request body as proper JSON struct: %v", err.Error()), http.StatusBadRequest)
		return
	}
	// Get the output from the witness.
	sth, err := s.w.Update(r.Context(), logID, req.STH, req.Proof)
	if err != nil {
		// If there was a failed precondition it's possible the caller was
		// just out of date.  Give the returned STH to help them
		// form a new request.
		if c := status.Code(err); c == codes.FailedPrecondition {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.WriteHeader(httpForCode(c))
			// The returned STH gets written a few lines below.
		} else {
			http.Error(w, fmt.Sprintf("failed to update to new STH: %v", err), httpForCode(http.StatusInternalServerError))
			return
		}
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Write(sth)
}

// getSTH returns an STH stored for a given log.
func (s *Server) getSTH(w http.ResponseWriter, r *http.Request) {
	v := mux.Vars(r)
	logID, err := url.PathUnescape(v["logid"])
	if err != nil {
		http.Error(w, fmt.Sprintf("cannot parse URL: %v", err.Error()), http.StatusBadRequest)
	}
	// Get the STH from the witness.
	sth, err := s.w.GetSTH(logID)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get STH: %v", err), httpForCode(status.Code(err)))
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Write(sth)
}

// getLogs returns a list of all logs the witness is aware of.
func (s *Server) getLogs(w http.ResponseWriter, r *http.Request) {
	logs, err := s.w.GetLogs()
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get log list: %v", err), http.StatusInternalServerError)
		return
	}
	logList, err := json.Marshal(logs)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to convert log list to JSON: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/json")
	w.Write(logList)
}

// RegisterHandlers registers HTTP handlers for witness endpoints.
func (s *Server) RegisterHandlers(r *mux.Router) {
	logStr := "{logid}"
	r.HandleFunc(fmt.Sprintf(api.HTTPGetSTH, logStr), s.getSTH).Methods("GET")
	r.HandleFunc(fmt.Sprintf(api.HTTPUpdate, logStr), s.update).Methods("PUT")
	r.HandleFunc(api.HTTPGetLogs, s.getLogs).Methods("GET")
}

func httpForCode(c codes.Code) int {
	switch c {
	case codes.NotFound:
		return http.StatusNotFound
	case codes.FailedPrecondition:
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}
