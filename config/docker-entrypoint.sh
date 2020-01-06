#!/bin/bash
set -e

function install_trillian(){
    echo "[1 of 3] installing tlserver"
    go install ./server/trillian_log_server
    echo "[2 of 3] installing tlsigner"
    go install ./server/trillian_log_signer
    echo "[3 of 3] installing create-tree utility"
    go install ./cmd/createtree
}

function install_ct(){
    echo "[1 of 1] install ct_server"
    go install ./trillian/ctfe/ct_server
}

function resetdb(){
    echo "resetting db..."
    sh -c "./scripts/resetdb.sh --force"
}

function create_tree(){
    echo "creating merkle tree"
    # admin_server is hardlinked to tlserver hostname
    # this will print out the tree_id created. required for later steps
    createtree --admin_server=tlserver:8090 --private_key_format=PrivateKey --pem_key_path=/go/src/github.com/google/trillian/testdata/log-rpc-server.privkey.pem --pem_key_password=towel --signature_algorithm=ECDSA
}

function tlserver(){
    echo "starting tlserver..."
    sh -c "trillian_log_server --config=/server.cfg"
}

function tlsigner(){
    echo "starting tlsigner..."
    sh -c "trillian_log_signer --config=/signer.cfg"
}

function ctserver(){
    echo "ct_server is (probably) good to go!"
}

while test $# -gt 0
do
    case "$1" in
        mysql) mysql -utest -pzaphod -hmysql cttest
            ;;
        bash) bash
            ;;
        --install-trillian) install_trillian
            ;;
        --install-ct) install_ct
            ;;
        --resetdb) resetdb
            ;;
        --createtree) create_tree
            ;;
        --tlserver) tlserver
            ;;
        --tlsigner) tlsigner
            ;;
        --ctserver) ctserver
            ;;
        *) echo "ignoring argument $1"
            ;;
    esac
    shift
done


exec "$@"
