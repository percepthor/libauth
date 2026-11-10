# Roadmap

What libauth has pending after 0.5, to be taken up in a later version. The pending items of the test suite are in
[test/roadmap.md](test/roadmap.md).

## Auth types

- `PERCEPTHOR_AUTH_TYPE_MULTIPLE` and `PERCEPTHOR_AUTH_TYPE_COMPLETE` exist in the enum, but a route of those types is
  always rejected: no service uses them and the auth service does not define what they check. Define what each one
  requires (and the body it sends to the auth service), or remove them.
- `PercepthorAuth.service` is never filled: the auth service does not answer the service of a service token. Fill it
  from the answer, or remove it.

## Requests

- Each authentication creates a new curl easy handle, so there is no reuse of the connection to the auth service: a
  handle (or a share of the connections) per thread would avoid a TCP handshake per request.
- `curl_global_cleanup ()` is never called, the global state of curl lives until the process ends.

## API

- The iterator of the permissions keeps its state in the `PercepthorAuth` (`next_permissions`), so two threads can
  not iterate the same one at the same time. An iterator owned by the caller would make it safe.
- The prefixes are not consistent (`percepthor_*`, `permissions_*`, `auth_route_*`, `auth_service_*`,
  `request_result_*`), and the lengths of the structs mix `int`, `unsigned int` and `size_t`.
- The install paths are fixed to `/usr/local` (`PREFIX` and `DESTDIR` are not supported).

## Tests

- The allocation failures (the paths of OOM) are only covered by reading: the tests have no hook to make `malloc ()`
  fail.
- The CI workflows exist, but they have not been seen green on GitHub yet.
- `make coverage` has no published report.
