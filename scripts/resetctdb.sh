#!/bin/bash

set -e

usage() {
  cat <<EOF
$(basename $0) [--force] [--verbose] ...
All unrecognised arguments will be passed through to the 'mysql' command.
Accepts environment variables:
- MYSQL_ROOT_USER: A user with sufficient rights to create/reset the CT
  database (default: root).
- MYSQL_ROOT_PASSWORD: The password for \$MYSQL_ROOT_USER (default: none).
- MYSQL_HOST: The hostname of the MySQL server (default: localhost).
- MYSQL_PORT: The port the MySQL server is listening on (default: 3306).
- MYSQL_DATABASE: The name to give to the new CT user and database
  (default: cttest).
- MYSQL_USER: The name to give to the new CT user (default: cttest).
- MYSQL_PASSWORD: The password to use for the new CT user
  (default: beeblebrox).
- MYSQL_USER_HOST: The host that the CT user will connect from; use '%' as
  a wildcard (default: localhost).
EOF
}

die() {
  echo "$*" > /dev/stderr
  exit 1
}

collect_vars() {
  # set unset environment variables to defaults
  [ -z ${MYSQL_ROOT_USER+x} ] && MYSQL_ROOT_USER="root"
  [ -z ${MYSQL_HOST+x} ] && MYSQL_HOST="localhost"
  [ -z ${MYSQL_PORT+x} ] && MYSQL_PORT="3306"
  [ -z ${MYSQL_DATABASE+x} ] && MYSQL_DATABASE="cttest"
  [ -z ${MYSQL_USER+x} ] && MYSQL_USER="cttest"
  [ -z ${MYSQL_PASSWORD+x} ] && MYSQL_PASSWORD="beeblebrox"
  [ -z ${MYSQL_USER_HOST+x} ] && MYSQL_USER_HOST="localhost"
  FLAGS=()

  # handle flags
  FORCE=false
  VERBOSE=false
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --force) FORCE=true ;;
      --verbose) VERBOSE=true ;;
      --help) usage; exit ;;
      *) FLAGS+=("$1")
    esac
    shift 1
  done

  FLAGS+=(-u "${MYSQL_ROOT_USER}")
  FLAGS+=(--host "${MYSQL_HOST}")
  FLAGS+=(--port "${MYSQL_PORT}")

  # Optionally print flags (before appending password)
  [[ ${VERBOSE} = 'true' ]] && echo "- Using MySQL Flags: ${FLAGS[@]}"

  # append password if supplied
  [ -z ${MYSQL_ROOT_PASSWORD+x} ] || FLAGS+=(-p"${MYSQL_ROOT_PASSWORD}")
}

main() {
  collect_vars "$@"

  readonly CT_GO_PATH=$(go list -f '{{.Dir}}' github.com/google/certificate-transparency-go)

  echo "Warning: about to destroy and reset database '${MYSQL_DATABASE}'"

  [[ ${FORCE} = true ]] || read -p "Are you sure? [Y/N]: " -n 1 -r
  echo # Print newline following the above prompt

  if [ -z ${REPLY+x} ] || [[ $REPLY =~ ^[Yy]$ ]]
  then
      echo "Resetting DB..."
      mysql "${FLAGS[@]}" -e "DROP DATABASE IF EXISTS ${MYSQL_DATABASE};" || \
        die "Error: Failed to drop database '${MYSQL_DATABASE}'."
      mysql "${FLAGS[@]}" -e "CREATE DATABASE ${MYSQL_DATABASE};" || \
        die "Error: Failed to create database '${MYSQL_DATABASE}'."
      mysql "${FLAGS[@]}" -e "CREATE USER IF NOT EXISTS ${MYSQL_USER}@'${MYSQL_USER_HOST}' IDENTIFIED BY '${MYSQL_PASSWORD}';" || \
        die "Error: Failed to create user '${MYSQL_USER}@${MYSQL_USER_HOST}'."
      mysql "${FLAGS[@]}" -e "GRANT ALL ON ${MYSQL_DATABASE}.* TO ${MYSQL_USER}@'${MYSQL_USER_HOST}'" || \
        die "Error: Failed to grant '${MYSQL_USER}' user all privileges on '${MYSQL_DATABASE}'."
      echo "Reset Complete"
  fi
}

main "$@"
