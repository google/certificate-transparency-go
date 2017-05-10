// Copyright 2016 Google Inc. All Rights Reserved.
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

package fixchain

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/google/certificate-transparency-go/x509"
)

// PostChainToLog attempts to post the given chain to the Certificate
// Transparency log at the given url, using the given http client.
// PostChainToLog returns a FixError if it is unable to post the chain either
// because client.Post() failed, or the http response code returned was not 200.
// It is up to the caller to handle such errors appropriately.
func PostChainToLog(chain []*x509.Certificate, client *http.Client, url string) *FixError {
	// Format the chain ready to be posted to the log.
	type Chain struct {
		Chain [][]byte `json:"chain"`
	}
	var m Chain
	for _, c := range chain {
		m.Chain = append(m.Chain, c.Raw)
	}
	j, err := json.Marshal(m)
	if err != nil {
		log.Fatalf("Can't marshal: %s", err)
	}

	// Post the chain!
	resp, err := client.Post(url+"/ct/v1/add-chain", "application/json", bytes.NewReader(j))
	if err != nil {
		return &FixError{
			Type:  PostFailed,
			Chain: chain,
			Error: fmt.Errorf("can't post: %s", err),
		}
	}

	defer resp.Body.Close()
	jo, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return &FixError{
			Type:  LogPostFailed,
			Chain: chain,
			Error: fmt.Errorf("can't read response: %s", err),
		}
	}

	if resp.StatusCode != 200 {
		return &FixError{
			Type:  LogPostFailed,
			Chain: chain,
			Error: fmt.Errorf("can't handle response code %d: %s", resp.StatusCode, jo),
			Code:  resp.StatusCode,
		}
	}

	return nil
}
