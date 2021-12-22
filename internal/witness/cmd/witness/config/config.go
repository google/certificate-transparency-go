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

// Package main is for populating the witness config file according to a set
// of logs.
package main

import (
	"encoding/base64"
	"flag"
	"io/ioutil"
	"net/http"

	"github.com/golang/glog"
	"github.com/google/certificate-transparency-go/internal/witness/cmd/witness/impl"
	"github.com/google/certificate-transparency-go/loglist2"
	"gopkg.in/yaml.v2"
)

var (
	logList    = flag.String("log_list_url", "https://www.gstatic.com/ct/log_list/v3/log_list.json", "The location of the log list")
	configFile = flag.String("config_file", "config.yaml", "path to a YAML config file that specifies the logs followed by this witness")
)

func main() {
	flag.Parse()
	var config impl.LogConfig
	// Get all usable logs from the log list.
	resp, err := http.Get(*logList)
	if err != nil {
		glog.Exitf("Failed to retrieve log list: %v", err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		glog.Exitf("Failed to read HTTP response: %v", err)
	}
	// Get data for all usable logs.
	logList, err := loglist2.NewFromJSON(body)
	if err != nil {
		glog.Exitf("failed to parse JSON: %v", err)
	}
	usable := logList.SelectByStatus([]loglist2.LogStatus{loglist2.UsableLogStatus})
	for _, operator := range usable.Operators {
		for _, log := range operator.Logs {
			key := base64.StdEncoding.EncodeToString(log.Key)
			l := impl.LogInfo{PubKey: key}
			config.Logs = append(config.Logs, l)
		}
	}
	data, err := yaml.Marshal(&config)
	if err != nil {
		glog.Exitf("Failed to marshal log config into YAML: %v", err)
	}
	if err := ioutil.WriteFile(*configFile, data, 0644); err != nil {
		glog.Exitf("Failed to write config to file: %v", err)
	}
}
