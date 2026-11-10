#ifndef _PERCEPTHOR_AUTH_ROUTES_H_
#define _PERCEPTHOR_AUTH_ROUTES_H_

#include "auth/auth.h"
#include "auth/config.h"
#include "auth/permissions.h"

/**
 * @file routes.h
 * @brief What a route requires from the token of its requests.
 *
 * An AuthRoute is the custom data of a route, a group or an endpoint of cerver,
 * released by cerver with auth_route_delete () when the route is deleted.
 */

#define AUTH_ROUTE_ACTION_SIZE			128
#define AUTH_ROUTE_ROLE_SIZE			128
#define AUTH_ROUTE_PERMISSIONS_SIZE		256

#ifdef __cplusplus
extern "C" {
#endif

/** @brief The authentication of a route: its type and what that type needs. */
typedef struct AuthRoute {

	PercepthorAuthType auth_type;
	PercepthorAuthScope auth_scope;

	int action_len;
	char action[AUTH_ROUTE_ACTION_SIZE];

	int role_len;
	char role[AUTH_ROUTE_ROLE_SIZE];

	PermissionsType permissions_type;

	int permissions_action_len;
	char permissions_action[AUTH_ROUTE_PERMISSIONS_SIZE];

} AuthRoute;

/**
 * @brief Releases an AuthRoute, the delete of the custom data of a route.
 * @param auth_route_ptr The AuthRoute, NULL does nothing.
 */
AUTH_EXPORT void auth_route_delete (void *auth_route_ptr);

/**
 * @brief Creates the AuthRoute of a route that only needs a valid token.
 * @return The AuthRoute, NULL on error.
 */
AUTH_EXPORT AuthRoute *auth_route_create (void);

/**
 * @brief Creates the AuthRoute of a route that needs an action of the role of the token.
 * @param action The action, truncated to AUTH_ROUTE_ACTION_SIZE.
 * @return The AuthRoute, NULL on error.
 */
AUTH_EXPORT AuthRoute *auth_route_create_action (const char *action);

/**
 * @brief Creates the AuthRoute of a route that needs a role, and optionally an action.
 * @param action The action, can be NULL.
 * @param role The role.
 * @return The AuthRoute, NULL on error.
 */
AUTH_EXPORT AuthRoute *auth_route_create_role (
	const char *action, const char *role
);

/**
 * @brief Creates the AuthRoute of a route that only accepts the token of a service.
 *
 * The AuthService of the cerver needs its service id.
 * @return The AuthRoute, NULL on error.
 */
AUTH_EXPORT AuthRoute *auth_route_create_service (void);

/**
 * @brief Creates the AuthRoute of a permissions route.
 *
 * A single route authenticates itself with percepthor_single_authentication () and the
 * resource of the request; a management route gets every resource of the type.
 * @param scope PERCEPTHOR_AUTH_SCOPE_SINGLE or PERCEPTHOR_AUTH_SCOPE_MANAGEMENT.
 * @param permissions_type The type of the resources.
 * @param permissions_action The action that the route needs, can be NULL.
 * @return The AuthRoute, NULL on error.
 */
AUTH_EXPORT AuthRoute *auth_route_create_permissions (
	const PercepthorAuthScope scope,
	const PermissionsType permissions_type,
	const char *permissions_action
);

/**
 * @brief Prints the values of an AuthRoute.
 * @param auth_route The AuthRoute, NULL does nothing.
 */
AUTH_EXPORT void auth_route_print (const AuthRoute *auth_route);

#ifdef __cplusplus
}
#endif

#endif
