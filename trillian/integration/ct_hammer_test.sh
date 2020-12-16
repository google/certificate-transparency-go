#!/bin/bash
set -e
. "$(go list -f '{{ .Dir }}' github.com/google/trillian)"/integration/functions.sh
INTEGRATION_DIR="$( cd "$( dirname "$0" )" && pwd )"
. "${INTEGRATION_DIR}"/ct_functions.sh

# We're not using Trillian's log setup/turn down, so allow the caller to
# specify where the trillian log server is.
export RPC_SERVERS=${TRILLIAN_LOG_SERVERS:-localhost:8090}
export RPC_SERVER_1=${TRILLIAN_LOG_SERVER_1:-localhost:8090}

go build ${GOFLAGS} github.com/google/certificate-transparency-go/trillian/integration/ct_hammer
ct_prep_test 1

# Cleanup for the personality
TO_DELETE="${TO_DELETE} ${CT_CFG}"
TO_KILL+=(${CT_SERVER_PIDS[@]})

metrics_port=$(pick_unused_port)
echo "Running test(s) with metrics at localhost:${metrics_port}"
set +e
./ct_hammer --log_config "${CT_CFG}" --ct_http_servers=${CT_SERVERS} --mmd=30s --testdata_dir=$(go list -f '{{ .Dir }}' github.com/google/certificate-transparency-go)/trillian/testdata --metrics_endpoint="localhost:${metrics_port}" --logtostderr ${HAMMER_OPTS}

RESULT=$?
set -e

ct_stop_test
TO_KILL=()

exit $RESULT
