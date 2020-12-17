# Functions for setting up CT personalities in Trillian integration tests
# Requires github.com/google/trillian/integration/functions.sh

declare -a CT_SERVER_PIDS
CT_SERVERS=
CT_CFG=
CT_LIFECYCLE_CFG=
CT_COMBINED_CFG=
PROMETHEUS_CFGDIR=
readonly CT_GO_PATH=$(go list -f '{{.Dir}}' github.com/google/certificate-transparency-go)

# ct_prep_test prepares a set of running processes for a CT test.
# Parameters:
#   - number of CT personality instances to run
# Populates:
#  - CT_SERVERS         : list of HTTP addresses (comma separated)
#  - CT_SERVER_1        : first HTTP address
#  - CT_METRICS_SERVERS : list of HTTP addresses (comma separated) serving metrics
#  - CT_SERVER_PIDS     : bash array of CT HTTP server pids
# in addition to the variables populated by log_prep_test.
# If etcd and Prometheus are configured, it also populates:
#  - ETCDISCOVER_PID   : pid of etcd service watcher
#  - PROMETHEUS_PID    : pid of local Prometheus server
#  - PROMETHEUS_CFGDIR : Prometheus configuration directory
ct_prep_test() {
  # Default to one of everything.
  local http_server_count=${1:-1}

  echo "PREP: Trillian: ${RPC_SERVER_1} [${RPC_SERVERS}]"

  echo "Building CT personality code"
  go build github.com/google/certificate-transparency-go/trillian/ctfe/ct_server

  echo "Provisioning logs for CT"
  ct_provision "${RPC_SERVER_1}"

  echo "Launching CT personalities"
  for ((i=0; i < http_server_count; i++)); do
    local port=$(pick_unused_port)
    CT_SERVERS="${CT_SERVERS},localhost:${port}"
    local metrics_port=$(pick_unused_port ${port})
    CT_METRICS_SERVERS="${CT_METRICS_SERVERS},localhost:${metrics_port}"
    if [[ $i -eq 0 ]]; then
      CT_SERVER_1="localhost:${port}"
    fi

    echo "Starting CT HTTP server on localhost:${port}, metrics on localhost:${metrics_port}"
    ./ct_server ${ETCD_OPTS} --log_config="${CT_COMBINED_CFG}" --log_rpc_server="${RPC_SERVERS}" --http_endpoint="localhost:${port}" --metrics_endpoint="localhost:${metrics_port}" ${CTFE_OPTS} &
    pid=$!
    CT_SERVER_PIDS+=(${pid})
    wait_for_server_startup ${port}
  done
  CT_SERVERS="${CT_SERVERS:1}"
  CT_METRICS_SERVERS="${CT_METRICS_SERVERS:1}"

  if [[ ! -z "${ETCD_OPTS}" ]]; then
    echo "Registered HTTP endpoints"
    ETCDCTL_API=3 etcdctl get trillian-ctfe-http/ --prefix
    ETCDCTL_API=3 etcdctl get trillian-ctfe-metrics-http/ --prefix
  fi

  if [[ -x "${PROMETHEUS_DIR}/prometheus" ]]; then
    if [[ ! -z "${ETCD_OPTS}" ]]; then
        PROMETHEUS_CFGDIR="$(mktemp -d ${TMPDIR}/ct-prometheus-XXXXXX)"
        local prom_cfg="${PROMETHEUS_CFGDIR}/config.yaml"
        local etcdiscovered="${PROMETHEUS_CFGDIR}/trillian.json"
        sed "s!@ETCDISCOVERED@!${etcdiscovered}!" ${CT_GO_PATH}/trillian/integration/prometheus.yml > "${prom_cfg}"
        echo "Prometheus configuration in ${prom_cfg}:"
        cat ${prom_cfg}

        echo "Building etcdiscover"
        go build github.com/google/trillian/monitoring/prometheus/etcdiscover

        echo "Launching etcd service monitor updating ${etcdiscovered}"
        ./etcdiscover ${ETCD_OPTS} --etcd_services=trillian-ctfe-metrics-http,trillian-logserver-http,trillian-logsigner-http -target=${etcdiscovered} --logtostderr &
        ETCDISCOVER_PID=$!
        echo "Launching Prometheus (default location localhost:9090)"
        ${PROMETHEUS_DIR}/prometheus --config.file=${prom_cfg} \
                           --web.console.templates=${CT_GO_PATH}/trillian/integration/consoles \
                           --web.console.libraries=${CT_GO_PATH}/third_party/prometheus/console_libs &
        PROMETHEUS_PID=$!
    fi
  fi
}

# ct_provision generates a CT configuration file and provisions the trees for it.
# Parameters:
#   - location of admin server instance
# Populates:
#   - CT_CFG           : configuration file for CT integration test
#   - CT_LIFECYCLE_CFG : configuration file for CT lifecycle test
#   - CT_COMBINED_CFG  : the above configs concatenated together
ct_provision() {
  local admin_server="$1"

  # Build config files with absolute paths
  CT_CFG=$(mktemp ${TMPDIR}/ct-XXXXXX)
  sed "s!@TESTDATA@!${CT_GO_PATH}/trillian/testdata!" ${CT_GO_PATH}/trillian/integration/ct_integration_test.cfg > "${CT_CFG}"

  CT_LIFECYCLE_CFG=$(mktemp ${TMPDIR}/ct-XXXXXX)
  sed "s!@TESTDATA@!${CT_GO_PATH}/trillian/testdata!" ${CT_GO_PATH}/trillian/integration/ct_lifecycle_test.cfg > "${CT_LIFECYCLE_CFG}"

  echo 'Building createtree'
  go build github.com/google/trillian/cmd/createtree/

  echo 'Provisioning Integration Logs'
  ct_provision_cfg ${admin_server} ${CT_CFG}
  echo 'Provisioning Lifecycle Logs'
  ct_provision_cfg ${admin_server} ${CT_LIFECYCLE_CFG}

  CT_COMBINED_CFG=$(mktemp ${TMPDIR}/ct-XXXXXX)
  cat ${CT_CFG} ${CT_LIFECYCLE_CFG} > ${CT_COMBINED_CFG}

  echo "CT Integration Configuration in ${CT_CFG}:"
  cat "${CT_CFG}"
  echo "CT Lifeycle Configuration in ${CT_LIFECYCLE_CFG}:"
  cat "${CT_LIFECYCLE_CFG}"
  echo
}

# ct_provision_cfg provisions trees for the logs in a specified config file.
# Parameters:
#   - location of admin server instance
#   - the config file to be provisioned for
ct_provision_cfg() {
  local admin_server="$1"
  local cfg="$2"

  num_logs=$(grep -c '@TREE_ID@' ${cfg})
  for i in $(seq ${num_logs}); do
    # TODO(daviddrysdale): Consider using distinct keys for each log
    tree_id=$(./createtree \
      --admin_server="${admin_server}" \
      --private_key_format=PrivateKey \
      --pem_key_path=${CT_GO_PATH}/trillian/testdata/log-rpc-server.privkey.pem \
      --pem_key_password=towel \
      --signature_algorithm=ECDSA)
    echo "Created tree ${tree_id}"
    # Need suffix for sed -i to cope with both GNU and non-GNU (e.g. OS X) sed.
    sed -i'.bak' "1,/@TREE_ID@/s/@TREE_ID@/${tree_id}/" "${cfg}"
    rm -f "${cfg}.bak"
  done
}

# ct_stop_test closes the running processes for a CT test.
# Assumes the following variables are set, in addition to those needed by logStopTest:
#  - CT_SERVER_PIDS  : bash array of CT HTTP server pids
ct_stop_test() {
  local pids
  if [[ "${PROMETHEUS_PID}" != "" ]]; then
    pids+=" ${PROMETHEUS_PID}"
  fi
  if [[ "${ETCDISCOVER_PID}" != "" ]]; then
    pids+=" ${ETCDISCOVER_PID}"
  fi
  echo "Stopping CT HTTP servers (pids ${CT_SERVER_PIDS[@]})"
  pids+=" ${CT_SERVER_PIDS[@]}"
  kill_pid ${pids}
}
