# Roadmap of the libauth suite

State on 2026-11-06 and what is missing. The procedure and the commands are in `test/README.md`.

## 1. Done

- **Unit:** a binary for each module (`auth`, `permissions`, `requests`, `routes`, `service`, `token`).
- **Integration:** an in-process cerver with the libauth routes of every type (token, action, role without action,
  service, management, single, multiple, without AuthRoute) and a stub of `/api/auth/check` that answers what each
  case asks for: 200/400/401/404/500, broken JSON, integer and string mask, an answer larger than the buffer, an
  unreachable service, a slow service, a cerver without AuthService and 8 concurrent clients.
- **Fuzz:** `response` (any answer, in every auth type) and `request` (the builders with arbitrary values: the body is
  always an object and the resource never adds fields).
- **Variants:** gcc, ASan + UBSan with `detect_leaks=1`, TSan, g++ and a fuzz of 30 s per target; `test/gate.sh`.

## 2. Bugs that it uncovered (fixed, each one with its test seen failing)

| Bug | Test |
|---|---|
| The JSON injection: the resource of the path (a decoded `%22`) added `"scope": 0` and auth-service answered 200 without checking the permissions | `unit/requests.c::test_requests_injection`, integration `single_injection` |
| `atoll (json_string_value ())` with an integer mask: segfault | `unit/auth.c::test_auth_response_mask`, integration `service` |
| A cerver without AuthService or a route without AuthRoute: segfault | integration `without_service`, `unsupported_types` |
| The single accepted an unreadable answer and left the custom data as NULL | integration `rejections` |
| The single sent the empty action of the route instead of its `permissions_action` | integration `single` |
| The role without action sent `"action": None` or `"action": ""` | `unit/requests.c::test_requests_role_without_action`, integration `role` |
| A body or a header longer than its buffer was sent truncated | `unit/requests.c::test_requests_body_too_large`, `test_requests_header_too_large` |
| The PercepthorAuth of a rejected answer was lost (leak) | ASan of the integration |
| Token values that are not strings with `"%s"` and NULL | `unit/auth.c::test_auth_response_token_types` |
| The getters, `permissions_*` and the `*_print` dereferenced NULL | `unit/auth.c::test_auth_getters_without_auth` and the ones of each module |
| The lengths of AuthRoute and AuthService were the ones that snprintf wanted to write | `unit/routes.c::test_routes_truncated`, `unit/service.c::test_service_truncated` |
| A service route of an AuthService without `service_id` was sent without the service: auth-service always answers 400. Now it is rejected (401) without calling auth-service | integration `service_without_id` |
| (0.5) An answer of more than 1 KB, like the management permissions of many resources, was rejected | integration `answer_grows` |
| (0.5) The `X-Forwarded-For` of a link local IPv6 with its zone did not fit and was not sent | `unit/requests.c::test_requests_client_zoned` |
| (0.5) A single with a resource and an action of 256 bytes did not fit in the body of 512 | `unit/requests.c::test_requests_single_permissions_limit` |
| (0.5) A `t_type` out of `PercepthorTokenType` was cast into the enum | `unit/auth.c::test_auth_response_token_type_unknown` |
| (0.5) `percepthor_auth_handle_response (NULL, ...)`: segfault | `unit/auth.c::test_auth_response_invalid` |
| (0.5) `libauth.so` also exported the `AUTH_PRIVATE` functions | `test/symbols.sh` |

## 3. Pending

What is pending of the library and of the suite is in [roadmap.md](../roadmap.md) at the root.
