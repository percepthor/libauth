#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "auth/auth.h"
#include "auth/permissions.h"
#include "auth/routes.h"

static AuthRoute *auth_route_new (void) {

	AuthRoute *auth_route = (AuthRoute *) malloc (sizeof (AuthRoute));
	if (auth_route) {
		(void) memset (auth_route, 0, sizeof (AuthRoute));
	}

	return auth_route;

}

void auth_route_delete (void *auth_route_ptr) {

	if (auth_route_ptr) {
		free (auth_route_ptr);
	}

}

AuthRoute *auth_route_create (void) {

	AuthRoute *auth_route = auth_route_new ();
	if (auth_route) {
		auth_route->auth_type = PERCEPTHOR_AUTH_TYPE_TOKEN;
	}

	return auth_route;

}

AuthRoute *auth_route_create_action (const char *action) {

	AuthRoute *auth_route = auth_route_new ();
	if (auth_route) {
		auth_route->auth_type = PERCEPTHOR_AUTH_TYPE_ACTION;

		auth_route->action_len = snprintf (
			auth_route->action, AUTH_ROUTE_ACTION_SIZE, "%s", action
		);
	}

	return auth_route;

}

AuthRoute *auth_route_create_role (const char *action, const char *role) {

	AuthRoute *auth_route = auth_route_new ();
	if (auth_route) {
		auth_route->auth_type = PERCEPTHOR_AUTH_TYPE_ROLE;

		if (action) {
			auth_route->action_len = snprintf (
				auth_route->action, AUTH_ROUTE_ACTION_SIZE, "%s", action
			);
		}

		if (role) {
			auth_route->role_len = snprintf (
				auth_route->role, AUTH_ROUTE_ROLE_SIZE, "%s", role
			);
		}
	}

	return auth_route;

}

AuthRoute *auth_route_create_service (void) {

	AuthRoute *auth_route = auth_route_new ();
	if (auth_route) {
		auth_route->auth_type = PERCEPTHOR_AUTH_TYPE_SERVICE;
	}

	return auth_route;

}

AuthRoute *auth_route_create_permissions (
	const PercepthorAuthScope scope,
	const PermissionsType permissions_type,
	const char *permissions_action
) {

	AuthRoute *auth_route = auth_route_new ();
	if (auth_route) {
		auth_route->auth_type = PERCEPTHOR_AUTH_TYPE_SERVICE;
		auth_route->auth_scope = scope;

		auth_route->permissions_type = permissions_type;

		if (permissions_action) {
			auth_route->permissions_action_len = snprintf (
				auth_route->permissions_action, AUTH_ROUTE_PERMISSIONS_SIZE,
				"%s", permissions_action
			);
		}
	}

	return auth_route;

}

void auth_route_print (const AuthRoute *auth_route) {

	if (auth_route) {
		(void) printf ("Auth Service:\n");

		(void) printf (
			"\ttype: %s\n", percepthor_auth_type_to_string (auth_route->auth_type)
		);

		(void) printf (
			"\tscope: %s\n", percepthor_auth_scope_to_string (auth_route->auth_scope)
		);

		if (auth_route->action_len > 0) {
			(void) printf (
				"\taction (%d): %s\n",
				auth_route->action_len, auth_route->action
			);
		}

		if (auth_route->role_len > 0) {
			(void) printf (
				"\trole (%d): %s\n",
				auth_route->role_len, auth_route->role
			);
		}

		if (auth_route->permissions_action_len > 0) {
			(void) printf (
				"\tpermissions action (%d): %s\n",
				auth_route->permissions_action_len, auth_route->permissions_action
			);
		}
	}

}
