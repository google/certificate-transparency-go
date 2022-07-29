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

// config is a tool to populate the witness config file according to a set of logs.
package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/google/certificate-transparency-go/internal/witness/cmd/witness/impl"
	"github.com/google/certificate-transparency-go/loglist3"
	"gopkg.in/yaml.v3"
	"k8s.io/klog/v2"
)

var (
	// This can be either an HTTP- or filesystem-based URL.
	logList    = flag.String("log_list_url", "https://www.gstatic.com/ct/log_list/v3/log_list.json", "The location of the log list")
	configFile = flag.String("config_file", "config.yaml", "path to a YAML config file that specifies the logs followed by this witness")
)

func main() {
	flag.Parse()
	// Get all usable logs from the log list.
	u, err := url.Parse(*logList)
	if err != nil {
		klog.Exitf("Failed to parse log_list_url as a URL: %v", err)
	}
	body, err := readURL(u)
	if err != nil {
		klog.Exitf("Failed to get log list data: %v", err)
	}
	// Get data for all usable logs.
	logList, err := loglist3.NewFromJSON(body)
	if err != nil {
		klog.Exitf("failed to parse JSON: %v", err)
	}
	var config impl.LogConfig
	usable := logList.SelectByStatus([]loglist3.LogStatus{loglist3.UsableLogStatus})
	for _, operator := range usable.Operators {
		for _, log := range operator.Logs {
			key := base64.StdEncoding.EncodeToString(log.Key)
			l := impl.LogInfo{PubKey: key}
			config.Logs = append(config.Logs, l)
		}
	}
	data, err := yaml.Marshal(&config)
	if err != nil {
		klog.Exitf("Failed to marshal log config into YAML: %v", err)
	}
	if err := os.WriteFile(*configFile, data, 0644); err != nil {
		klog.Exitf("Failed to write config to file: %v", err)
	}
}

var getByScheme = map[string]func(*url.URL) ([]byte, error){
	"http":  readHTTP,
	"https": readHTTP,
	"file": func(u *url.URL) ([]byte, error) {
		return os.ReadFile(u.Path)
	},
}

// readHTTP fetches and reads data from an HTTP-based URL.
func readHTTP(u *url.URL) ([]byte, error) {
	resp, err := http.Get(u.String())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// readURL fetches and reads data from an HTTP-based or filesystem URL.
func readURL(u *url.URL) ([]byte, error) {
	s := u.Scheme
	queryFn, ok := getByScheme[s]
	if !ok {
		return nil, fmt.Errorf("failed to identify suitable scheme for the URL %q", u.String())
	}
	return queryFn(u)
}
