# libauth tests

The suite of libauth, cloned from the one of cerver (`cerver/test/`): unit binaries, an in-process
integration against a stub of the auth service, libFuzzer targets, the sanitizers and a flaky hunter.
Every test of a bug fails against the code before its fix (seen with the baseline of the version before the fix).

## Layout

| Path | What |
|---|---|
| `test/test.h` | The macros of the checks, a byte-for-byte copy of `cerver/test/test.h` |
| `test/unit/*.c` | One binary per module: `auth`, `permissions`, `requests`, `routes`, `service`, `token` |
| `test/integration/integration.c` | One web cerver in a thread with the routes of libauth and a stub of `/api/auth/check` in the same cerver; a raw socket client |
| `test/fuzz/{response,request}.c` | libFuzzer: the answers of the auth service and the requests to it |
| `test/run.sh` | Runs the symbols check and every binary from the root; `RUNNER` wraps them (valgrind) |
| `test/symbols.sh` | `libauth.so` exports exactly the `AUTH_EXPORT` and `AUTH_PUBLIC` functions of the headers; the binaries link the objects of the library, so they reach the `AUTH_PRIVATE` ones |
| `test/build.sh` | The test image, `SANITIZER=` (none), `address,undefined` or `thread` |
| `test/repeat.sh` | `test/repeat.sh test/bin/integration [count]`, stops at the first failure; `TEST_AUTH_CASE` picks a case |
| `test/fuzz.sh` | `SECONDS_PER_TARGET=30 bash test/fuzz.sh [target...]`; the seeds are written on every run, never committed |
| `test/gate.sh` | The gate before publishing: every variant, g++ and the fuzzers, from `make clean` |
| `Dockerfile.test`, `Dockerfile.fuzz` | cerver from its local sources (`--build-context cerver=<path>`), with the same sanitizer |

## Running

```bash
bash test/build.sh                                   # itpercepthor/libauth:test
docker run --rm itpercepthor/libauth:test bash test/run.sh

SANITIZER=address,undefined bash test/build.sh
docker run --rm --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
	-e ASAN_OPTIONS=detect_leaks=1 itpercepthor/libauth:test-address-undefined bash test/run.sh

SANITIZER=thread bash test/build.sh
docker run --rm --security-opt seccomp=unconfined itpercepthor/libauth:test-thread bash test/run.sh

TEST_AUTH_CASE=single_injection SANITIZER=thread bash test/repeat.sh test/bin/integration 50
SECONDS_PER_TARGET=30 bash test/fuzz.sh
bash test/gate.sh                                    # everything, ~15 min
```

## Rules

- The test build lowers `AUTH_REQUEST_TIMEOUT` and `AUTH_REQUEST_CONNECT_TIMEOUT` to 2 s (`TESTTIMEOUTS` in the
  makefile), so the slow auth service case takes seconds; production keeps 30 s and 10 s.
- The stub of the auth service is a group of the same cerver, with enough threads for a request to wait for the
  stub in another one. Before cerver 2.0b-60 that was the only way: the responses and the pools of cerver were
  released by the first web cerver of a process that ended (`percepthor-backend/docs/backlog/cerver-findings.md`
  §14); since 2.0b-60 they are shared until the last one ends.
- A client waits on a condition, never with a fixed sleep; the only sleep is the one of the slow stub.
