#!/bin/bash

# builds the test image: SANITIZER= (none), address,undefined or thread
DOCKER=${DOCKER:-docker}
SANITIZER=${SANITIZER:-}
CERVER_DIR=${CERVER_DIR:-/Users/ermiry/Documents/cerver-http}

if [ -n "$SANITIZER" ]; then
	IMAGE=${IMAGE:-itpercepthor/libauth:test-$(echo "$SANITIZER" | tr ',' '-')}
else
	IMAGE=${IMAGE:-itpercepthor/libauth:test}
fi

cd "$(dirname "$0")/.." || exit 1

$DOCKER build \
	--build-context cerver="$CERVER_DIR" \
	--build-arg SANITIZER="$SANITIZER" \
	-t "$IMAGE" -f Dockerfile.test .
