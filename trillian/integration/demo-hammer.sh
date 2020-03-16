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

#echo '-----------------------------------------------'
set -x

## this is all done in prior parts of setup
echo 'Manually edit CT config file to put the tree ID value in place of @TREE_ID@. This needs to be explicitly copied from the server logs.'
tree_id=2092664048943921845
server_ip=40.114.31.88
prefix=athos
sed -i'.bak' "1,/@TREE_ID@/s/@TREE_ID@/${tree_id}/" demo-script.cfg
# enable for ctserverb
#sed -i'.bak' "s/athos/porthos/" demo-script.cfg

echo 'Log is now accessible -- see in browser window'
${URLOPEN} http://${server_ip}:6965/${prefix}/ct/v1/get-sth

echo 'The Hammer test tool populates the server with data'
go install ./trillian/integration/ct_hammer

echo 'CT_Hammer runs until interrupted. For some reason the log server times out after 6K entries.. :/ <6K is ok though'
ct_hammer --log_config demo-script.cfg --ct_http_servers=${server_ip}:6965 --mmd=30s --testdata_dir=${GOPATH}/src/github.com/zorawar87/certificate-transparency-go/trillian/testdata --logtostderr
hammer_pid=$!
