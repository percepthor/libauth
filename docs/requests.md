# Requests

`#include <auth/requests.h>`

Each authentication is a `POST` to the address of the `AuthService`:

| Part | Value |
|---|---|
| `Authorization` | The token of the request, as it came (`Bearer <token>`) |
| `X-Forwarded-For` | The address of the client of the request, when cerver knows it |
| `X-Request-Id` | The id of the request, when cerver has one (`http_cerver_set_request_id ()`) |
| Body | A JSON object with the `type` of the route, the `source` (the name of the service) and what the type requires: `action`, `role`, `service`, or `scope`, `permissions_type`, `resource` and `action` |

The body is serialized with the JSON of cerver, so a value (like a resource from a path) can not add fields to it.

## Limits

A request that does not fit fails closed: it is never sent truncated, and the request to the route is a 401.

| Define | Size |
|---|---|
| `AUTH_HEADER_SIZE` | 1024, the `Authorization` header |
| `AUTH_REQUEST_SIZE` | 4096, the body: it fits a resource and an action of 256 bytes even when every byte is escaped |
| `AUTH_FORWARDED_HEADER_SIZE` | 128, a link local IPv6 address with its zone |
| `AUTH_REQUEST_ID_HEADER_SIZE` | 128, the longest request id of cerver |
| `AUTH_RESPONSE_INITIAL_SIZE` | 1024, the first buffer of the answer, it doubles while the answer grows |
| `AUTH_RESPONSE_MAX_SIZE` | 65536, the largest answer, it can be changed with `-D AUTH_RESPONSE_MAX_SIZE=<size>` |
| `AUTH_REQUEST_CONNECT_TIMEOUT` | 10 seconds to connect to the auth service |
| `AUTH_REQUEST_TIMEOUT` | 30 seconds for the whole request |

The requests never use signals for their timeouts (`CURLOPT_NOSIGNAL`), they run in the threads of a cerver.

## The answer

The auth service answers 200 with a JSON object, any other status or an answer that is not an object rejects the
request:

| Key | Read into |
|---|---|
| `token` | The `AuthToken` (`id`, `t_type`, `organization`, `permissions`, `role`, `user`, `username`) |
| `mask` | The actions mask of a service route, a number or a string |
| `resources` | The `Permissions` of a management route: `[{"_id": "...", "actions": ["..."]}]` |
| `admin` | Whether the user is a super admin |
