#!/bin/bash

# runs a test binary until it fails or reaches the count, to find a flaky test;
# TEST_AUTH_CASE selects a single case of the integration
DOCKER=${DOCKER:-docker}
SANITIZER=${SANITIZER:-}
BUILD=${BUILD:-1}
RUN_SECONDS=${RUN_SECONDS:-120}

TARGET="$1"
COUNT="${2:-100}"

if [ -z "$TARGET" ]; then
	echo "usage: test/repeat.sh <test/bin/...> [count]"
	exit 2
fi

if [ ! -f /.dockerenv ]; then
	cd "$(dirname "$0")/.." || exit 1

	if [ -n "$SANITIZER" ]; then
		IMAGE=${IMAGE:-itpercepthor/libauth:test-$(echo "$SANITIZER" | tr ',' '-')}
	else
		IMAGE=${IMAGE:-itpercepthor/libauth:test}
	fi

	if [ "$BUILD" -ne 0 ]; then
		SANITIZER="$SANITIZER" IMAGE="$IMAGE" bash test/build.sh || exit 1
	fi

	exec $DOCKER run --rm \
		--cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
		-e ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=1}" \
		-e UBSAN_OPTIONS="${UBSAN_OPTIONS:-print_stacktrace=1:halt_on_error=1}" \
		-e TSAN_OPTIONS="${TSAN_OPTIONS:-halt_on_error=1:second_deadlock_stack=1}" \
		-e TEST_AUTH_CASE="${TEST_AUTH_CASE:-}" \
		-e RUN_SECONDS="$RUN_SECONDS" \
		"$IMAGE" bash test/repeat.sh "$TARGET" "$COUNT"
fi

for (( run = 1; run <= COUNT; run++ )); do
	if [ -z "$TEST_AUTH_CASE" ]; then unset TEST_AUTH_CASE; fi

	if ! timeout "$RUN_SECONDS" "./$TARGET" > /tmp/repeat.log 2>&1; then
		tail -n 64 /tmp/repeat.log
		echo "$TARGET failed in run $run of $COUNT"
		exit 1
	fi
done

echo "$TARGET passed $COUNT runs"
