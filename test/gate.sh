#!/bin/bash

# the gate before publishing libauth: every variant from clean sources
# gcc, address + undefined, thread, g++ without new warnings, and the fuzzers
DOCKER=${DOCKER:-docker}
SECONDS_PER_TARGET=${SECONDS_PER_TARGET:-30}

cd "$(dirname "$0")/.." || exit 1

FAILED=()

step () {
	local name="$1"
	shift

	echo "==== $name"
	if "$@"; then
		echo "==== $name: ok"
	else
		echo "==== $name: failed"
		FAILED+=("$name")
	fi
}

make clean

step "build" bash test/build.sh
step "build address,undefined" env SANITIZER=address,undefined bash test/build.sh
step "build thread" env SANITIZER=thread bash test/build.sh

step "gcc" $DOCKER run --rm itpercepthor/libauth:test bash test/run.sh

step "address,undefined" $DOCKER run --rm \
	--cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
	-e ASAN_OPTIONS="detect_leaks=1" \
	-e UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1" \
	itpercepthor/libauth:test-address-undefined bash test/run.sh

step "thread" $DOCKER run --rm \
	--security-opt seccomp=unconfined \
	-e TSAN_OPTIONS="halt_on_error=1:second_deadlock_stack=1" \
	itpercepthor/libauth:test-thread bash test/run.sh

# the warnings of g++ are compared by hand against the ones of the last gate
step "g++" $DOCKER run --rm itpercepthor/libauth:test bash -c 'make clean > /dev/null && make CC=g++ TYPE=test -j8'

step "fuzz" env SECONDS_PER_TARGET="$SECONDS_PER_TARGET" bash test/fuzz.sh

make clean

printf "\n%d failed\n" "${#FAILED[@]}"

if [ ${#FAILED[@]} -gt 0 ]; then
	printf "failed: %s\n" "${FAILED[*]}"
	exit 1
fi
