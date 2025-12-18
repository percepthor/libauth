#!/bin/bash

# runs every test binary from the repository root; RUNNER wraps each one (valgrind)
RUNNER=${RUNNER:-}

run () {
	$RUNNER "$@" || { echo "$1 failed"; exit 1; }
}

run bash ./test/symbols.sh

run ./test/bin/auth

run ./test/bin/permissions

run ./test/bin/requests

run ./test/bin/routes

run ./test/bin/service

run ./test/bin/token

run ./test/bin/integration
