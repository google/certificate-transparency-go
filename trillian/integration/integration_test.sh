#!/bin/bash
set -e

# Import Trillian integration functions for kill_pid, pick_unused_port, etc.,
# but we no longer use the log prep/tear down stuff.
. "$(go list -f '{{ .Dir }}' github.com/google/trillian)"/integration/functions.sh

run_test "CT integration test" "$(go list -f '{{ .Dir }}' github.com/google/certificate-transparency-go)/trillian/integration/ct_integration_test.sh" 1
run_test "CT multi-server integration test" "$(go list -f '{{ .Dir }}' github.com/google/certificate-transparency-go)/trillian/integration/ct_integration_test.sh" 3
