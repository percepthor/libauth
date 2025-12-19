# Permissions

`#include <auth/permissions.h>`

A management permissions route (`auth_route_create_permissions (PERCEPTHOR_AUTH_SCOPE_MANAGEMENT, type, action)`) gets
from the auth service every resource of the type over which the user has the action, and whether the user is a super
admin. They are a list of `Permissions` in the `PercepthorAuth` of the request:

``` c
PercepthorAuth *auth = (PercepthorAuth *) http_request_get_custom_data (request);

if (percepthor_auth_get_admin (auth)) {
	// every resource
}

else if (percepthor_auth_permissions_iter_start (auth)) {
	const Permissions *permissions = NULL;
	while ((permissions = percepthor_auth_permissions_iter_get_next (auth))) {
		const char *resource = permissions_get_resource (permissions);

		if (permissions_has_action (permissions, "tickets.update")) {
			// the user can update the tickets of the resource
		}
	}
}
```

| Type | Resources |
|---|---|
| `PERMISSIONS_TYPE_SERVICE` | Services |
| `PERMISSIONS_TYPE_ORGANIZATION` | Organizations |
| `PERMISSIONS_TYPE_PROJECT` | Projects |

`permissions_type_to_string ()` and `permissions_print ()` print them. An answer of up to `AUTH_RESPONSE_MAX_SIZE`
bytes (64 KB) is read, so a user with many resources is still authenticated.
