# Build

## Library

``` bash
make clean
make TYPE=<type> -j8
sudo make TYPE=<type> install
```

| Variable | Values |
|---|---|
| `TYPE` | `development` (the default, with `PERCEPTHOR_DEBUG` logs), `test` (with the lower limits of the tests), `beta`, `production` |
| `SANITIZER` | The `-fsanitize` of the library and the tests, like `address,undefined` or `thread` |
| `NATIVE` | `1` for `-march=native` |
| `COVERAGE` | `1` with `TYPE=test` for gcov |
| `CC` | `gcc` (the default), `g++` or `clang` |

The library is compiled with `-fvisibility=hidden`: `libauth.so` only exports the `AUTH_EXPORT` and `AUTH_PUBLIC`
functions. `make install` copies it to `/usr/local/lib` and the headers to `/usr/local/include/auth`.

## Tests

| Command | |
|---|---|
| `bash test/build.sh` | The test image, with cerver from `CERVER_DIR` (`SANITIZER` builds a variant) |
| `docker run --rm itpercepthor/libauth:test bash test/run.sh` | The symbols check, every unit binary and the integration |
| `TEST_AUTH_CASE=<case> ./test/bin/integration` | A single case of the integration |
| `bash test/repeat.sh test/bin/integration 20` | A binary many times, to find a flaky test |
| `bash test/fuzz.sh` | The fuzzers (`response` and `request`) with libFuzzer |
| `bash test/gate.sh` | Every variant from clean sources: gcc, address + undefined, thread, g++ and the fuzzers |

The tests link the objects of the library, so they reach its `AUTH_PRIVATE` functions too. The test build lowers the
timeouts of a request and `AUTH_RESPONSE_MAX_SIZE` (4096), so the stub of the integration can answer one that does
not fit. See [test/README.md](../test/README.md).
