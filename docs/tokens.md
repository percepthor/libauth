# Tokens

`#include <auth/token.h>`

The auth service answers the values of the token of every authenticated request. They are the `AuthToken` of the
`PercepthorAuth`, read with its getters:

| Value | Getter | Size |
|---|---|---|
| `id` | `percepthor_auth_get_token_id ()` | `AUTH_ID_SIZE` |
| `type` | `percepthor_auth_get_token_type ()` | `PercepthorTokenType` |
| `organization` | `percepthor_auth_get_token_organization ()` | `AUTH_ID_SIZE` |
| `permissions` | `percepthor_auth_get_token_permissions ()` | `AUTH_ID_SIZE` |
| `role` | `percepthor_auth_get_token_role ()` | `AUTH_ID_SIZE` |
| `user` | `percepthor_auth_get_token_user ()` | `AUTH_ID_SIZE` |
| `username` | `percepthor_auth_get_token_username ()` | `AUTH_TOKEN_USERNAME_SIZE` |

A value that is not a string is read as an empty one, and a longer one is truncated. `AUTH_ID_SIZE` fits an
ObjectId (24 characters).

The types are the ones that the auth service gives to its tokens: `PERCEPTHOR_TOKEN_TYPE_NORMAL` (1),
`_TEMPORARY` (2), `_QUANTITY` (3) and `_USER` (4). A type that is not one of these is read as
`PERCEPTHOR_TOKEN_TYPE_NONE`. `percepthor_token_type_to_string ()` and
`percepthor_token_print ()` print them.
