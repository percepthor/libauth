# Routes

`#include <auth/routes.h>`

An `AuthRoute` is what a route requires from the token of its requests. It is the custom data of a route, a group or
an endpoint of cerver, and cerver releases it with `auth_route_delete ()` when the route is deleted:

``` c
http_endpoint_set_custom_data (endpoint, auth_route_create_action ("tickets.create"), auth_route_delete);
```

| Function | Route |
|---|---|
| `auth_route_create ()` | A valid token |
| `auth_route_create_action (action)` | An action of the role of the token |
| `auth_route_create_role (action, role)` | A role, the action can be `NULL` |
| `auth_route_create_service ()` | The token of a service |
| `auth_route_create_permissions (scope, permissions_type, action)` | The permissions over a resource (`PERCEPTHOR_AUTH_SCOPE_SINGLE`) or over every resource of a type (`PERCEPTHOR_AUTH_SCOPE_MANAGEMENT`) |
| `auth_route_print (auth_route)` | Prints the values |

A value longer than its buffer (`AUTH_ROUTE_ACTION_SIZE`, `AUTH_ROUTE_ROLE_SIZE`, `AUTH_ROUTE_PERMISSIONS_SIZE`) is
truncated, and its length is the one of the stored value.

A group passes its `AuthRoute` to its endpoints that do not have their own, so a group can require a token and one of
its endpoints an action.

## Single permissions routes

A single route does not use the authentication handler: its handler calls `percepthor_single_authentication ()` with
the resource of the request, so the check runs with the value of the path:

``` c
static void ticket_get_handler (const HttpReceive *http_receive, const HttpRequest *request) {

	const String *ticket_id = http_request_get_param_at_idx (request, 0);

	if (!percepthor_single_authentication (http_receive, request, ticket_id->str)) {
		// the user has the permissions action of the route over the ticket
	}

}
```
