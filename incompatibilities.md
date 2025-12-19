# Incompatibilities

The changes of each version that can break code or binaries built with the version before it, the newest first.
Unlike `CHANGELOG.md`, which only has the current version, every entry stays here.

## 0.5 (from 0.4.4)

- libauth needs cerver 2.0 (2.0b-64 or newer): it reads the custom data of the routes and of the cerver with
  `http_receive_get_route_custom_data ()` and `http_receive_get_cerver_custom_data ()`, 0.4.4 read the fields of cerver
  1.x directly
- `libauth.so` only exports the `AUTH_EXPORT` and `AUTH_PUBLIC` functions: a binary that called an `AUTH_PRIVATE` one
  (`permissions_create ()`, `permissions_delete ()`, `permissions_action_create ()`, `permissions_action_delete ()`,
  `percepthor_auth_handle_response ()` or the `auth_request_*` builders) no longer links. `auth_service_new ()` and
  `auth_service_delete ()` are `AUTH_EXPORT` now
- New fields (ABI): `AuthRequest` changed completely (`auth_header_len`, `forwarded_header`, `request_id_header`, and
  its answer is a buffer that grows, `response` is a `char *` released with `auth_request_end ()`)
- `AUTH_REQUEST_SIZE` is 4096 (it was 512), the new `AUTH_FORWARDED_HEADER_SIZE` and `AUTH_REQUEST_ID_HEADER_SIZE`
  are 128, and `AUTH_RESPONSE_SIZE` was replaced by `AUTH_RESPONSE_INITIAL_SIZE` (1024) and
  `AUTH_RESPONSE_MAX_SIZE` (65536, overridable with a define)
- An answer of the auth service up to 64 KB is read: 0.4.4 rejected any answer larger than 1 KB, like the management
  permissions of many resources
- The getters `percepthor_auth_get_type ()`, `_get_scope ()`, `_get_admin ()`, `_get_token_type ()` and `_get_mask ()`
  return their values without `const` (the same values, it only changes the prototypes)
- A `t_type` of the token that is not a `PercepthorTokenType` is read as `PERCEPTHOR_TOKEN_TYPE_NONE`, 0.4.4 cast it
  into the enum
- A 200 of the auth service without a body is a failed request
- A permissions `PercepthorAuth` whose list of permissions could not be created is not created
  (`percepthor_auth_create ()` returns NULL), so the request is rejected
- A service route of an `AuthService` without its id is rejected without calling the auth service
- The `PercepthorAuth` of a service route is created with `PERCEPTHOR_AUTH_TYPE_SERVICE`, so
  `percepthor_auth_get_type ()` returns it: 0.4.4 created it with `percepthor_auth_new ()` and its type was
  `PERCEPTHOR_AUTH_TYPE_NONE`
- The request to the auth service carries the `X-Forwarded-For` and the `X-Request-Id` of the request that it
  authenticates, when cerver knows them
- `auth_service_print ()` prints the address of the auth service as "Address"
