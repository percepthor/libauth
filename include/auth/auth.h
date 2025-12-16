#ifndef _PERCEPTHOR_AUTH_H_
#define _PERCEPTHOR_AUTH_H_

#include <stdbool.h>
#include <stdint.h>

#include <cerver/collections/dlist.h>

#include "auth/config.h"
#include "auth/permissions.h"
#include "auth/token.h"
#include "auth/types.h"

/**
 * @file auth.h
 * @brief The authentication of the requests of a cerver against the auth service.
 *
 * A route is authenticated by percepthor_custom_authentication_handler () (or by
 * percepthor_single_authentication () from its own handler): libauth sends the token
 * of the request to the auth service with what the route requires (its AuthRoute,
 * see routes.h), and when the service accepts it, the values it answered are kept
 * in a PercepthorAuth as the custom data of the request, released with the request.
 */

#ifdef __cplusplus
extern "C" {
#endif

struct _HttpReceive;
struct _HttpRequest;

struct _Permissions;

#define PERCEPTHOR_AUTH_TYPE_MAP(XX)		\
	XX(0,  NONE,      		None)			\
	XX(1,  TOKEN,      		Token)			\
	XX(2,  ACTION,      	Action)			\
	XX(3,  ROLE,  			Role)			\
	XX(4,  SERVICE,			Service)		\
	XX(5,  PERMISSIONS,		Permissions)	\
	XX(6,  MULTIPLE,		Multiple)		\
	XX(7,  COMPLETE,		Complete)

/**
 * @brief What a route requires from the token of a request.
 *
 * TOKEN only needs a valid token, ACTION an action of its role, ROLE a role,
 * SERVICE the token of a service and PERMISSIONS the permissions of a resource.
 * MULTIPLE and COMPLETE are reserved: a route of those types is always rejected.
 */
typedef enum PercepthorAuthType {

	#define XX(num, name, string) PERCEPTHOR_AUTH_TYPE_##name = num,
	PERCEPTHOR_AUTH_TYPE_MAP(XX)
	#undef XX

} PercepthorAuthType;

/**
 * @brief Returns the name of an auth type.
 * @param type The type.
 * @return A static string, "None" for an unknown type.
 */
AUTH_PUBLIC const char *percepthor_auth_type_to_string (
	const PercepthorAuthType type
);

#define PERCEPTHOR_AUTH_SCOPE_MAP(XX)	\
	XX(0,  NONE,      	None)			\
	XX(1,  SINGLE,      Single)			\
	XX(2,  MANAGEMENT,  Management)

/**
 * @brief The scope of a PERCEPTHOR_AUTH_TYPE_PERMISSIONS route: a single resource
 * (from the path of the request) or the management of every resource of a type.
 */
typedef enum PercepthorAuthScope {

	#define XX(num, name, string) PERCEPTHOR_AUTH_SCOPE_##name = num,
	PERCEPTHOR_AUTH_SCOPE_MAP(XX)
	#undef XX

} PercepthorAuthScope;

/**
 * @brief Returns the name of an auth scope.
 * @param scope The scope.
 * @return A static string, "None" for an unknown scope.
 */
AUTH_PUBLIC const char *percepthor_auth_scope_to_string (
	const PercepthorAuthScope scope
);

/**
 * @brief The values of an authenticated request, as the auth service answered them.
 *
 * It is the custom data of the request (http_request_get_custom_data ()), and it is
 * released with the request. Read it with the getters, that accept NULL.
 */
typedef struct PercepthorAuth {

	PercepthorAuthType type;
	PercepthorAuthScope scope;

	/** @brief Reserved, never filled (see roadmap.md). */
	char service[AUTH_ID_SIZE];

	PermissionsType permissions_type;
	char resource[AUTH_RESOURCE_SIZE];
	char action[AUTH_ACTION_SIZE];

	bool super_admin;

	DoubleList *permissions;

	/** @brief The state of the iterator of the permissions, it is not thread safe. */
	ListElement *next_permissions;

	AuthToken token;

	int64_t mask;

} PercepthorAuth;

/**
 * @brief Releases a PercepthorAuth and its permissions.
 * @param auth_ptr The PercepthorAuth, NULL does nothing.
 */
AUTH_PUBLIC void percepthor_auth_delete (void *auth_ptr);

/**
 * @brief Returns the type of the route that authenticated the request.
 * @param percepthor_auth The auth values, can be NULL.
 * @return The type, PERCEPTHOR_AUTH_TYPE_NONE for NULL.
 */
AUTH_EXPORT PercepthorAuthType percepthor_auth_get_type (
	const PercepthorAuth *percepthor_auth
);

/**
 * @brief Returns the scope of a permissions route.
 * @param percepthor_auth The auth values, can be NULL.
 * @return The scope, PERCEPTHOR_AUTH_SCOPE_NONE for NULL or a route without one.
 */
AUTH_EXPORT PercepthorAuthScope percepthor_auth_get_scope (
	const PercepthorAuth *percepthor_auth
);

/**
 * @brief Returns the resource of a single permissions route.
 * @param percepthor_auth The auth values, can be NULL.
 * @return The resource, NULL for NULL.
 */
AUTH_EXPORT const char *percepthor_auth_get_resource (
	const PercepthorAuth *percepthor_auth
);

/**
 * @brief Returns the action of a single permissions route.
 * @param percepthor_auth The auth values, can be NULL.
 * @return The action, NULL for NULL.
 */
AUTH_EXPORT const char *percepthor_auth_get_action (
	const PercepthorAuth *percepthor_auth
);

/**
 * @brief Returns whether the auth service answered that the user is a super admin.
 * @param percepthor_auth The auth values, can be NULL.
 * @return true for an admin, false for NULL.
 */
AUTH_EXPORT bool percepthor_auth_get_admin (
	const PercepthorAuth *percepthor_auth
);

/**
 * @brief Returns the permissions of a management permissions route.
 * @param percepthor_auth The auth values, can be NULL.
 * @return A list of Permissions, NULL for NULL or for any other route.
 */
AUTH_EXPORT DoubleList *percepthor_auth_get_permissions (
	const PercepthorAuth *percepthor_auth
);

/**
 * @brief Starts the iteration of the permissions.
 *
 * The state of the iteration lives in the PercepthorAuth, so two threads can not
 * iterate the same one at the same time.
 * @param percepthor_auth The auth values.
 * @return true when there are permissions to iterate.
 */
AUTH_EXPORT bool percepthor_auth_permissions_iter_start (PercepthorAuth *percepthor_auth);

/**
 * @brief Returns the next permissions of the iteration.
 * @param percepthor_auth The auth values, after percepthor_auth_permissions_iter_start ().
 * @return The Permissions, NULL after the last one.
 */
AUTH_EXPORT const struct _Permissions *percepthor_auth_permissions_iter_get_next (
	PercepthorAuth *percepthor_auth
);

/**
 * @brief Returns the id of the token.
 * @param percepthor_auth The auth values, can be NULL.
 * @return The id, NULL for NULL.
 */
AUTH_EXPORT const char *percepthor_auth_get_token_id (
	const PercepthorAuth *percepthor_auth
);

/**
 * @brief Returns the type of the token.
 * @param percepthor_auth The auth values, can be NULL.
 * @return The type, PERCEPTHOR_TOKEN_TYPE_NONE for NULL.
 */
AUTH_EXPORT PercepthorTokenType percepthor_auth_get_token_type (
	const PercepthorAuth *percepthor_auth
);

/**
 * @brief Returns the organization of the token.
 * @param percepthor_auth The auth values, can be NULL.
 * @return The organization, NULL for NULL.
 */
AUTH_EXPORT const char *percepthor_auth_get_token_organization (
	const PercepthorAuth *percepthor_auth
);

/**
 * @brief Returns the permissions of the token.
 * @param percepthor_auth The auth values, can be NULL.
 * @return The permissions, NULL for NULL.
 */
AUTH_EXPORT const char *percepthor_auth_get_token_permissions (
	const PercepthorAuth *percepthor_auth
);

/**
 * @brief Returns the role of the token.
 * @param percepthor_auth The auth values, can be NULL.
 * @return The role, NULL for NULL.
 */
AUTH_EXPORT const char *percepthor_auth_get_token_role (
	const PercepthorAuth *percepthor_auth
);

/**
 * @brief Returns the user of the token.
 * @param percepthor_auth The auth values, can be NULL.
 * @return The user, NULL for NULL.
 */
AUTH_EXPORT const char *percepthor_auth_get_token_user (
	const PercepthorAuth *percepthor_auth
);

/**
 * @brief Returns the username of the token.
 * @param percepthor_auth The auth values, can be NULL.
 * @return The username, NULL for NULL.
 */
AUTH_EXPORT const char *percepthor_auth_get_token_username (
	const PercepthorAuth *percepthor_auth
);

/**
 * @brief Returns the actions mask that the auth service answered for a service route.
 * @param percepthor_auth The auth values, can be NULL.
 * @return The mask, 0 for NULL.
 */
AUTH_EXPORT int64_t percepthor_auth_get_mask (
	const PercepthorAuth *percepthor_auth
);

/**
 * @brief Creates the auth values of a type, a permissions one with its list.
 * @param type The type.
 * @return The PercepthorAuth, released with percepthor_auth_delete (), NULL on error.
 */
AUTH_PUBLIC PercepthorAuth *percepthor_auth_create (
	const PercepthorAuthType type
);

/**
 * @brief Prints the token of the auth values.
 * @param percepthor_auth The auth values, NULL does nothing.
 */
AUTH_EXPORT void percepthor_auth_print_token (
	const PercepthorAuth *percepthor_auth
);

// reads the response of the auth service into the auth values,
// returns 0 when it is a json object
AUTH_PRIVATE unsigned int percepthor_auth_handle_response (
	PercepthorAuth *percepthor_auth, const char *response
);

/**
 * @brief Authenticates a request with the permissions of a single resource.
 *
 * It is called by the handler of a route whose AuthRoute was created with
 * auth_route_create_permissions (PERCEPTHOR_AUTH_SCOPE_SINGLE, ...), with the
 * resource of the request (like a param of its path). When the auth service
 * accepts it, the PercepthorAuth is the custom data of the request.
 * @param http_receive The HttpReceive of the request.
 * @param request The request.
 * @param resource The resource.
 * @return 0 when the request was authenticated, 1 otherwise.
 */
AUTH_EXPORT unsigned int percepthor_single_authentication (
	const struct _HttpReceive *http_receive,
	const struct _HttpRequest *request,
	const char *resource
);

/**
 * @brief The authentication handler of the routes of a cerver (an HttpAuthenticationHandler).
 *
 * It authenticates the request with the AuthRoute of the route (its custom data) and
 * the AuthService of the cerver (the custom data of the HTTP cerver). When the auth
 * service accepts it, the PercepthorAuth is the custom data of the request.
 * @param http_receive The HttpReceive of the request.
 * @param request The request.
 * @return 0 when the request was authenticated, 1 otherwise.
 */
AUTH_EXPORT unsigned int percepthor_custom_authentication_handler (
	const struct _HttpReceive *http_receive,
	const struct _HttpRequest *request
);

#ifdef __cplusplus
}
#endif

#endif
