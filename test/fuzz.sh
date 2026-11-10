#!/bin/bash

# fuzzes the answers of the auth service and the requests to it with libFuzzer;
# the seeds are written on every run, the corpus is never committed
DOCKER=${DOCKER:-docker}
IMAGE=${IMAGE:-itpercepthor/libauth:fuzz}
BUILD=${BUILD:-1}
CERVER_DIR=${CERVER_DIR:-/Users/ermiry/Documents/cerver-http}
SECONDS_PER_TARGET=${SECONDS_PER_TARGET:-30}
MAX_LENGTH=${MAX_LENGTH:-4096}
ARTIFACTS=${ARTIFACTS:-fuzz-artifacts}

TARGETS=(response request)

if [ $# -gt 0 ]; then
	TARGETS=("$@")
fi

if [ ! -f /.dockerenv ]; then
	if [ "$BUILD" -ne 0 ]; then
		$DOCKER build --build-context cerver="$CERVER_DIR" -t "$IMAGE" -f Dockerfile.fuzz . || exit 1
	fi

	mkdir -p "$ARTIFACTS"

	exec $DOCKER run --rm \
		-v "$(pwd)/$ARTIFACTS:/opt/libauth/$ARTIFACTS" \
		-e SECONDS_PER_TARGET="$SECONDS_PER_TARGET" \
		-e MAX_LENGTH="$MAX_LENGTH" \
		-e ARTIFACTS="$ARTIFACTS" \
		"$IMAGE" bash test/fuzz.sh "${TARGETS[@]}"
fi

seeds () {
	local corpus="$1" target="$2"

	case "$target" in
		response)
			printf '%s' '{"token": {"id": "507f1f77bcf86cd799439011", "t_type": 4, "organization": "507f1f77bcf86cd799439012", "role": "507f1f77bcf86cd799439013", "user": "507f1f77bcf86cd799439014", "username": "erick"}}' > "$corpus/token"
			printf '%s' '{"token": {"id": "507f1f77bcf86cd799439011"}, "mask": 12}' > "$corpus/mask"
			printf '%s' '{"token": {"id": "507f1f77bcf86cd799439011"}, "mask": "12"}' > "$corpus/mask-string"
			printf '%s' '{"admin": true, "resources": [{"_id": "507f1f77bcf86cd799439015", "actions": ["read", "write"]}]}' > "$corpus/resources"
			printf '%s' '{"oki": "doki"}' > "$corpus/oki"
			;;
		request)
			printf 'Bearer token\ntickets\ntickets.create\n507f1f77bcf86cd799439012' > "$corpus/single"
			printf 'Bearer token\ntickets\na"b\nx", "scope": 0, "y": "' > "$corpus/injection"
			;;
	esac
}

FAILED=()
for target in "${TARGETS[@]}"; do
	echo "Fuzzing $target for $SECONDS_PER_TARGET seconds..."

	corpus="/tmp/fuzz-corpus/$target"
	mkdir -p "$corpus" "$ARTIFACTS"
	seeds "$corpus" "$target"

	if ! ./test/bin/fuzz/$target "$corpus" \
		-max_total_time="$SECONDS_PER_TARGET" \
		-max_len="$MAX_LENGTH" \
		-timeout=10 \
		-print_final_stats=1 \
		-artifact_prefix="$ARTIFACTS/$target-" > "/tmp/fuzz-$target.log" 2>&1; then
		FAILED+=("$target")
		tail -n 64 "/tmp/fuzz-$target.log"
	else
		grep -E "stat::number_of_executed_units|stat::new_units_added" "/tmp/fuzz-$target.log"
	fi
done

printf "\n%d targets - %d failed\n" "${#TARGETS[@]}" "${#FAILED[@]}"

if [ ${#FAILED[@]} -gt 0 ]; then
	printf "failed: %s\n" "${FAILED[*]}"
	exit 1
fi
