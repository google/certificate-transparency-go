#!/bin/bash
set -e
. "$(go list -f '{{ .Dir }}' github.com/google/trillian)"/integration/functions.sh
INTEGRATION_DIR="$( cd "$( dirname "$0" )" && pwd )"
. "${INTEGRATION_DIR}"/ct_functions.sh

# We're not using Trillian's log setup/turn down, so allow the caller to
# specify where the trillian log server is.
export RPC_SERVERS=${TRILLIAN_LOG_SERVERS:-localhost:8090}
export RPC_SERVER_1=${TRILLIAN_LOG_SERVER_1:-localhost:8090}

ct_prep_test 1

# Cleanup for the personality
TO_DELETE="${TO_DELETE} ${CT_CFG} ${CT_LIFECYCLE_CFG} ${CT_COMBINED_CONFIG}"
TO_KILL+=(${CT_SERVER_PIDS[@]})

COMMON_ARGS="--ct_http_servers=${CT_SERVERS} --ct_metrics_servers=${CT_METRICS_SERVERS} --testdata_dir="$(go list -f '{{ .Dir }}' github.com/google/certificate-transparency-go)"/trillian/testdata"

echo "Running test(s)"
pushd "${INTEGRATION_DIR}"
set +e
go test -v -run ".*LiveCT.*" --timeout=5m ./ --log_config "${CT_CFG}" ${COMMON_ARGS}
RESULT=$?
set -e
popd

# Integration test run failed? Clean up and exit if so
if [[ "${RESULT}" != "0" ]]; then
  ct_stop_test
  TO_KILL=()

  exit $RESULT
fi

# Now run the lifecycle test. This will use the same servers but with a
# different set of empty logs.
pushd "${INTEGRATION_DIR}"
set +e
go test -v -run ".*LiveLifecycle.*" --timeout=5m ./ --log_config "${CT_LIFECYCLE_CFG}" --admin_server="${RPC_SERVER_1}" ${COMMON_ARGS}
RESULT=$?
set -e
popd

ct_stop_test
TO_KILL=()

exit $RESULT
