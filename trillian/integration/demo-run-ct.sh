#!/bin/bash
# This is a linear script for demonstrating a Trillian-backed CT log; its contents
# are extracted from the main trillian/integration/ct_integration_test.sh script.
## Zorawar added some notes below. they start with two hashes


if [ $(uname) == "Darwin" ]; then
  URLOPEN=open
else
  URLOPEN=curl
fi
hash ${URLOPEN} 2>/dev/null || { echo >&2 "WARNING: ${URLOPEN} not found - browser windows will fail to open"; }
if [[ ! -d "${GOPATH}" ]]; then
  echo "Error: GOPATH not set"
  exit 1
fi
if [[ ${PWD} -ef ${GOPATH}/src/github.com/zorawar87/certificate-transparency-go/trillian/integration ]]; then
  echo "Error: cannot run from directory ${PWD}; try: cd ../..; ./trillian/integration/demo-script.sh"
  exit 1
fi

echo 'Prepared before demo: edit trillian/integration/demo-script.cfg to fill in local GOPATH'
sed "s~@TESTDATA@~${GOPATH}/src/github.com/zorawar87/certificate-transparency-go/trillian/testdata~" ${GOPATH}/src/github.com/zorawar87/certificate-transparency-go/trillian/integration/demo-script.cfg > demo-script.cfg

echo '-----------------------------------------------'
set -x

## this is all done in prior parts of setup
#echo 'Reset MySQL database'
#yes | ${GOPATH}/src/github.com/google/trillian/scripts/resetdb.sh
#
#echo 'Building Trillian log code'
#go build github.com/google/trillian/server/trillian_log_server/
#go build github.com/google/trillian/server/trillian_log_signer/
#
#echo 'Start a Trillian Log server (do in separate terminal)'
#./trillian_log_server --rpc_endpoint=localhost:6962 --http_endpoint=localhost:6963 --logtostderr &
#
#echo 'Start a Trillian Log signer (do in separate terminal)'
#./trillian_log_signer --force_master --sequencer_interval=1s --batch_size=500 --rpc_endpoint=localhost:6961 --http_endpoint=localhost:6964 --num_sequencers 2 --logtostderr &
#
#echo 'Wait for things to come up'
#sleep 8
#
#echo 'Building provisioning tool'
#go build github.com/google/trillian/cmd/createtree/
#
#echo 'Provision a log and remember the its tree ID'
tree_id=$(createtree --admin_server=tlserver:8090 --private_key_format=PrivateKey --pem_key_path=${GOPATH}/src/github.com/zorawar87/certificate-transparency-go/trillian/testdata/log-rpc-server.privkey.pem --pem_key_password=towel --signature_algorithm=ECDSA)
echo ${tree_id}

echo 'Manually edit CT config file to put the tree ID value in place of @TREE_ID@'
sed -i'.bak' "1,/@TREE_ID@/s/@TREE_ID@/${tree_id}/" demo-script.cfg

## we already install this
#echo 'Building CT personality code'
#go build github.com/zorawar87/certificate-transparency-go/trillian/ctfe/ct_server

echo 'Running the CT personality in non-interactive mode'
ct_server --log_config=demo-script.cfg --log_rpc_server=tlserver:8090 --http_endpoint=0.0.0.0:6965 -alsologtostderr -v=2
