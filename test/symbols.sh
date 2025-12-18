#!/bin/bash

# libauth.so exports exactly the AUTH_EXPORT and AUTH_PUBLIC functions of its headers:
# an AUTH_PRIVATE function that is exported, or a public one that is missing, fails
LIBRARY=${LIBRARY:-bin/libauth.so}
HEADERS=${HEADERS:-include/auth}

declared=$(grep -hoE 'AUTH_(EXPORT|PUBLIC)[^;(]*\(' "$HEADERS"/*.h \
	| sed -E 's/[[:space:]]*\($//; s/.*[[:space:]*]//' | sort -u)

# _init and _fini of the linker are not functions of libauth
exported=$(nm -D --defined-only "$LIBRARY" | awk '($2 == "T") && ($3 !~ /^_/) { print $3 }' | sort -u)

missing=$(comm -23 <(echo "$declared") <(echo "$exported"))
extra=$(comm -13 <(echo "$declared") <(echo "$exported"))

printf "%d declared - %d exported\n" "$(echo "$declared" | wc -l)" "$(echo "$exported" | wc -l)"

if [ -n "$missing" ]; then
	printf "declared but not exported:\n%s\n" "$missing"
fi

if [ -n "$extra" ]; then
	printf "exported but not declared public:\n%s\n" "$extra"
fi

[ -z "$missing" ] && [ -z "$extra" ]
