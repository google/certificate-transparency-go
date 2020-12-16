#!/bin/bash

# This script is used by the CloudBuild ct_testbase docker image.
# It's executed as the default command by that image in order to run a
# full presubmit/integration test.
# It's equivalent to the "script:" section in the travis config.

./scripts/presubmit.sh ${PRESUBMIT_OPTS}

# Check re-generation didn't change anything
status=$(git status --porcelain | egrep -v 'coverage|go\.(mod|sum)') || :
if [[ -n ${status} ]]; then
  echo "Regenerated files differ from checked-in versions: ${status}"
  git status
  git diff
  #exit 1
fi

if [[ "${WITH_ETCD}" == "true" ]]; then
  export ETCD_DIR="${GOPATH}/bin"
fi

./trillian/integration/integration_test.sh

HAMMER_OPTS="--operations=1500" ./trillian/integration/ct_hammer_test.sh
