# Auth

`#include <auth/auth.h>`

## How a request is authenticated

1. The HTTP cerver of the service has its `AuthService` as its custom data (see [services.md](services.md)).
2. A route, a group or an endpoint has its `AuthRoute` as its custom data (see [routes.md](routes.md)), and
   `percepthor_custom_authentication_handler ()` as its authentication handler with `HTTP_ROUTE_AUTH_TYPE_CUSTOM`.
3. For each request, the handler reads the `Authorization` header, the `AuthService` and the `AuthRoute`, and sends
   the token to the auth service with what the route requires (see [requests.md](requests.md)).
4. When the auth service answers 200, its answer is read into a `PercepthorAuth`, which becomes the custom data of the
   request (`http_request_get_custom_data ()`) and is released with it. Any other answer is a 401.

A request without a token, a cerver without its `AuthService` or a route without its `AuthRoute` is always rejected.

## The authentication handlers

| Function | When |
|---|---|
| `percepthor_custom_authentication_handler (http_receive, request)` | The authentication handler of a route, it runs before the handler of the route |
| `percepthor_single_authentication (http_receive, request, resource)` | Called by the handler of a single permissions route, with the resource of the request (like a param of its path) |

Both return 0 when the request was authenticated.

## Auth types

| Type | Requires |
|---|---|
| `PERCEPTHOR_AUTH_TYPE_TOKEN` | A valid token |
| `PERCEPTHOR_AUTH_TYPE_ACTION` | An action of the role of the token |
| `PERCEPTHOR_AUTH_TYPE_ROLE` | A role, and optionally an action |
| `PERCEPTHOR_AUTH_TYPE_SERVICE` | The token of a service, with the id of the `AuthService` |
| `PERCEPTHOR_AUTH_TYPE_PERMISSIONS` | The permissions over a single resource or over every resource of a type (`PERCEPTHOR_AUTH_SCOPE_SINGLE` / `_MANAGEMENT`) |
| `PERCEPTHOR_AUTH_TYPE_MULTIPLE`, `_COMPLETE` | Reserved, always rejected (see [roadmap.md](../roadmap.md)) |

## The PercepthorAuth of a request

Every getter accepts `NULL`, the custom data of a request that libauth did not authenticate:

| Getter | Value |
|---|---|
| `percepthor_auth_get_type`, `_get_scope` | The type and the scope of the route |
| `percepthor_auth_get_token_id`, `_type`, `_organization`, `_permissions`, `_role`, `_user`, `_username` | The values of the token (see [tokens.md](tokens.md)) |
| `percepthor_auth_get_resource`, `_get_action` | The resource and the action of a single permissions route |
| `percepthor_auth_get_permissions` | The permissions of a management route (see [permissions.md](permissions.md)) |
| `percepthor_auth_get_admin` | Whether the user is a super admin |
| `percepthor_auth_get_mask` | The actions mask of a service route |

`percepthor_auth_permissions_iter_start ()` and `percepthor_auth_permissions_iter_get_next ()` iterate the
permissions. The state of the iteration lives in the `PercepthorAuth`, so two threads can not iterate the same one at
the same time.
