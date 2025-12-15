#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <cerver/collections/dlist.h>

#include <cerver/http/http.h>
#include <cerver/http/request.h>

#include <cerver/http/json/json.h>

#include <cerver/utils/log.h>

#include "auth/auth.h"
#include "auth/permissions.h"
#include "auth/requests.h"
#include "auth/routes.h"
#include "auth/service.h"
#include "auth/token.h"

const char *percepthor_auth_type_to_string (const PercepthorAuthType type) {

	switch (type) {
		#define XX(num, name, string) case PERCEPTHOR_AUTH_TYPE_##name: return #string;
		PERCEPTHOR_AUTH_TYPE_MAP(XX)
		#undef XX
	}

	return percepthor_auth_type_to_string (PERCEPTHOR_AUTH_TYPE_NONE);

}

const char *percepthor_auth_scope_to_string (const PercepthorAuthScope scope) {

	switch (scope) {
		#define XX(num, name, string) case PERCEPTHOR_AUTH_SCOPE_##name: return #string;
		PERCEPTHOR_AUTH_SCOPE_MAP(XX)
		#undef XX
	}

	return percepthor_auth_scope_to_string (PERCEPTHOR_AUTH_SCOPE_NONE);

}

static PercepthorAuth *percepthor_auth_new (void) {

	PercepthorAuth *auth = (PercepthorAuth *) malloc (sizeof (PercepthorAuth));
	if (auth) {
		(void) memset (auth, 0, sizeof (PercepthorAuth));

		auth->type = PERCEPTHOR_AUTH_TYPE_NONE;
		auth->scope = PERCEPTHOR_AUTH_SCOPE_NONE;

		auth->permissions = NULL;
		auth->next_permissions = NULL;
	}

	return auth;

}

void percepthor_auth_delete (void *auth_ptr) {

	if (auth_ptr) {
		PercepthorAuth *percepthor_auth = (PercepthorAuth *) auth_ptr;

		dlist_delete (percepthor_auth->permissions);

		free (auth_ptr);
	}

}

// every getter accepts the NULL custom data of a request
// that was not authenticated by libauth
PercepthorAuthType percepthor_auth_get_type (
	const PercepthorAuth *percepthor_auth
) {

	return percepthor_auth ? percepthor_auth->type : PERCEPTHOR_AUTH_TYPE_NONE;

}

PercepthorAuthScope percepthor_auth_get_scope (
	const PercepthorAuth *percepthor_auth
) {

	return percepthor_auth ? percepthor_auth->scope : PERCEPTHOR_AUTH_SCOPE_NONE;

}

const char *percepthor_auth_get_resource (
	const PercepthorAuth *percepthor_auth
) {

	return percepthor_auth ? percepthor_auth->resource : NULL;

}

const char *percepthor_auth_get_action (
	const PercepthorAuth *percepthor_auth
) {

	return percepthor_auth ? percepthor_auth->action : NULL;

}

bool percepthor_auth_get_admin (
	const PercepthorAuth *percepthor_auth
) {

	return percepthor_auth ? percepthor_auth->super_admin : false;

}

static void percepthor_auth_set_admin (
	PercepthorAuth *percepthor_auth, const bool is_admin
) {

	percepthor_auth->super_admin = is_admin;

}

DoubleList *percepthor_auth_get_permissions (
	const PercepthorAuth *percepthor_auth
) {

	return percepthor_auth ? percepthor_auth->permissions : NULL;

}

bool percepthor_auth_permissions_iter_start (
	PercepthorAuth *percepthor_auth
) {

	bool retval = false;

	if (percepthor_auth) {
		if (percepthor_auth->permissions) {
			if (dlist_start (percepthor_auth->permissions)) {
				percepthor_auth->next_permissions = dlist_start (
					percepthor_auth->permissions
				);

				retval = true;
			}
		}
	}

	return retval;

}

const Permissions *percepthor_auth_permissions_iter_get_next (
	PercepthorAuth *percepthor_auth
) {

	const Permissions *permissions = NULL;

	if (percepthor_auth && percepthor_auth->next_permissions) {
		permissions = (const Permissions *) percepthor_auth->next_permissions->data;
		percepthor_auth->next_permissions = percepthor_auth->next_permissions->next;
	}

	return permissions;

}

const char *percepthor_auth_get_token_id (
	const PercepthorAuth *percepthor_auth
) {

	return percepthor_auth ? percepthor_auth->token.id : NULL;

}

PercepthorTokenType percepthor_auth_get_token_type (
	const PercepthorAuth *percepthor_auth
) {

	return percepthor_auth ? percepthor_auth->token.type : PERCEPTHOR_TOKEN_TYPE_NONE;

}

const char *percepthor_auth_get_token_organization (
	const PercepthorAuth *percepthor_auth
) {

	return percepthor_auth ? percepthor_auth->token.organization : NULL;

}

const char *percepthor_auth_get_token_permissions (
	const PercepthorAuth *percepthor_auth
) {

	return percepthor_auth ? percepthor_auth->token.permissions : NULL;

}

const char *percepthor_auth_get_token_role (
	const PercepthorAuth *percepthor_auth
) {

	return percepthor_auth ? percepthor_auth->token.role : NULL;

}

const char *percepthor_auth_get_token_user (
	const PercepthorAuth *percepthor_auth
) {

	return percepthor_auth ? percepthor_auth->token.user : NULL;

}

const char *percepthor_auth_get_token_username (
	const PercepthorAuth *percepthor_auth
) {

	return percepthor_auth ? percepthor_auth->token.username : NULL;

}

int64_t percepthor_auth_get_mask (
	const PercepthorAuth *percepthor_auth
) {

	return percepthor_auth ? percepthor_auth->mask : 0;

}

// the permissions of a management route are read into their list,
// so a permissions auth without its list is not created at all
static PercepthorAuth *percepthor_auth_create_permissions (PercepthorAuth *percepthor_auth) {

	percepthor_auth->permissions = dlist_init (permissions_delete, NULL);
	if (!percepthor_auth->permissions) {
		percepthor_auth_delete (percepthor_auth);
		percepthor_auth = NULL;
	}

	return percepthor_auth;

}

PercepthorAuth *percepthor_auth_create (const PercepthorAuthType type) {

	PercepthorAuth *percepthor_auth = percepthor_auth_new ();
	if (percepthor_auth) {
		percepthor_auth->type = type;

		switch (percepthor_auth->type) {
			case PERCEPTHOR_AUTH_TYPE_NONE: break;

			case PERCEPTHOR_AUTH_TYPE_TOKEN: break;
			case PERCEPTHOR_AUTH_TYPE_ACTION: break;
			case PERCEPTHOR_AUTH_TYPE_ROLE: break;
			case PERCEPTHOR_AUTH_TYPE_SERVICE: break;

			case PERCEPTHOR_AUTH_TYPE_PERMISSIONS:
				percepthor_auth = percepthor_auth_create_permissions (percepthor_auth);
				break;

			case PERCEPTHOR_AUTH_TYPE_MULTIPLE: break;
			case PERCEPTHOR_AUTH_TYPE_COMPLETE: break;

			default: break;
		}
	}

	return percepthor_auth;

}

void percepthor_auth_print_token (const PercepthorAuth *percepthor_auth) {

	if (percepthor_auth) {
		percepthor_token_print (&percepthor_auth->token);
	}

}

// copies a string of the response; any other json type leaves the destination empty
static void percepthor_auth_copy_string (
	char *destination, const size_t size, const json_t *value
) {

	if (json_is_string (value)) {
		(void) snprintf (destination, size, "%s", json_string_value (value));
	}

	else {
		destination[0] = '\0';
	}

}

// a type that is not one of PercepthorTokenType is read as PERCEPTHOR_TOKEN_TYPE_NONE,
// it is never cast into a value that the enum does not have
static PercepthorTokenType percepthor_auth_parse_token_type (const json_t *value) {

	PercepthorTokenType type = PERCEPTHOR_TOKEN_TYPE_NONE;

	if (json_is_integer (value)) {
		switch (json_integer_value (value)) {
			#define XX(num, name, string) case num: type = PERCEPTHOR_TOKEN_TYPE_##name; break;
			PERCEPTHOR_TOKEN_TYPE_MAP(XX)
			#undef XX

			default: break;
		}
	}

	return type;

}

static void percepthor_auth_parse_token (AuthToken *token, json_t *json_object) {

	const char *key = NULL;
	json_t *value = NULL;
	json_object_foreach (json_object, key, value) {
		if (!strcmp (key, "id")) {
			percepthor_auth_copy_string (token->id, AUTH_ID_SIZE, value);
		}

		else if (!strcmp (key, "t_type")) {
			token->type = percepthor_auth_parse_token_type (value);
		}

		else if (!strcmp (key, "organization")) {
			percepthor_auth_copy_string (token->organization, AUTH_ID_SIZE, value);
		}

		else if (!strcmp (key, "permissions")) {
			percepthor_auth_copy_string (token->permissions, AUTH_ID_SIZE, value);
		}

		else if (!strcmp (key, "role")) {
			percepthor_auth_copy_string (token->role, AUTH_ID_SIZE, value);
		}

		else if (!strcmp (key, "user")) {
			percepthor_auth_copy_string (token->user, AUTH_ID_SIZE, value);
		}

		else if (!strcmp (key, "username")) {
			percepthor_auth_copy_string (token->username, AUTH_TOKEN_USERNAME_SIZE, value);
		}
	}

}

// the auth service answers the mask as a number or as the string it read from redis
static int64_t percepthor_auth_parse_mask (const json_t *value) {

	int64_t mask = 0;

	if (json_is_integer (value)) {
		mask = (int64_t) json_integer_value (value);
	}

	else if (json_is_string (value)) {
		mask = (int64_t) strtoll (json_string_value (value), NULL, 10);
	}

	return mask;

}

// an action that could not be created or inserted is released, never leaked
static void percepthor_auth_parse_action (Permissions *permissions, const json_t *action) {

	PermissionsAction *permissions_action = permissions_action_create (json_string_value (action));
	if (permissions_action) {
		if (dlist_insert_after_unsafe (
			permissions->actions, dlist_end (permissions->actions), permissions_action
		)) {
			permissions_action_delete (permissions_action);
		}
	}

}

static void percepthor_auth_parse_single_resource (
	Permissions *permissions, json_t *json_object
) {

	const char *key = NULL;
	json_t *value = NULL;
	json_object_foreach (json_object, key, value) {
		if (!strcmp (key, "_id")) {
			percepthor_auth_copy_string (permissions->resource, AUTH_RESOURCE_SIZE, value);
		}

		else if (!strcmp (key, "actions")) {
			if (json_is_array (value)) {
				const size_t n_actions = json_array_size (value);
				for (size_t i = 0; i < n_actions; i++) {
					const json_t *action = json_array_get (value, i);
					if (json_is_string (action)) {
						percepthor_auth_parse_action (permissions, action);
					}
				}
			}
		}
	}

}

static void percepthor_auth_parse_resources (
	PercepthorAuth *percepthor_auth, json_t *resources_array
) {

	const size_t n_resources = json_array_size (resources_array);
	for (size_t i = 0; i < n_resources; i++) {
		json_t *json_object = json_array_get (resources_array, i);
		if (json_is_object (json_object)) {
			Permissions *permissions = permissions_create ();
			if (permissions) {
				percepthor_auth_parse_single_resource (permissions, json_object);

				if (dlist_insert_after_unsafe (
					percepthor_auth->permissions,
					dlist_end (percepthor_auth->permissions),
					permissions
				)) {
					permissions_delete (permissions);
				}
			}
		}
	}

}

// reads every value the auth service can answer: the token, the actions mask
// of a service, the resources of the management permissions and the admin flag
unsigned int percepthor_auth_handle_response (
	PercepthorAuth *percepthor_auth, const char *response
) {

	unsigned int retval = 1;

	json_error_t json_error = { 0 };
	json_t *json_body = (percepthor_auth && response) ? json_loads (response, 0, &json_error) : NULL;
	if (json_body) {
		if (json_is_object (json_body)) {
			const char *key = NULL;
			json_t *value = NULL;
			json_object_foreach (json_body, key, value) {
				if (!strcmp (key, "token")) {
					if (json_is_object (value)) {
						percepthor_auth_parse_token (&percepthor_auth->token, value);
					}
				}

				else if (!strcmp (key, "mask")) {
					percepthor_auth->mask = percepthor_auth_parse_mask (value);
				}

				else if (!strcmp (key, "resources")) {
					if (percepthor_auth->permissions && json_is_array (value)) {
						percepthor_auth_parse_resources (percepthor_auth, value);
					}
				}

				else if (!strcmp (key, "admin")) {
					if (json_is_boolean (value)) {
						percepthor_auth_set_admin (percepthor_auth, json_boolean_value (value));
					}
				}
			}

			retval = 0;
		}

		json_decref (json_body);
	}

	#ifdef PERCEPTHOR_DEBUG
	else {
		cerver_log_error (
			"percepthor_auth_handle_response () - json error on line %d: %s\n",
			json_error.line, json_error.text
		);
	}
	#endif

	return retval;

}

static void percepthor_single_authentication_internal (
	const HttpRequest *request, AuthRequest *auth_request,
	const PermissionsType permissions_type, const char *resource, const char *action
) {

	PercepthorAuth *percepthor_auth = percepthor_auth_create (PERCEPTHOR_AUTH_TYPE_PERMISSIONS);

	percepthor_auth->scope = PERCEPTHOR_AUTH_SCOPE_SINGLE;
	percepthor_auth->permissions_type = permissions_type;

	(void) snprintf (percepthor_auth->resource, AUTH_RESOURCE_SIZE, "%s", resource);
	(void) snprintf (percepthor_auth->action, AUTH_ACTION_SIZE, "%s", action);

	// get token values from response's body
	if (!percepthor_auth_handle_response (
		percepthor_auth, auth_request->response
	)) {
		#ifdef PERCEPTHOR_DEBUG
		cerver_log_success ("Success auth!");
		#endif

		http_request_set_custom_data (
			(HttpRequest *) request, percepthor_auth
		);

		http_request_set_delete_custom_data (
			(HttpRequest *) request, percepthor_auth_delete
		);
	}

}

unsigned int percepthor_single_authentication (
	const HttpReceive *http_receive, const HttpRequest *request,
	const char *resource
) {

	unsigned int retval = 1;

	// get the token from the request's headers
	const String *token = http_request_get_header (
		request, HTTP_HEADER_AUTHORIZATION
	);

	if (token) {
		const AuthService *auth_service = (
			const AuthService *
		) http_receive->http_cerver->custom_data;

		const AuthRoute *auth_route = (
			const AuthRoute *
		) http_receive->route->custom_data;

		AuthRequest auth_request = { 0 };
		auth_request_create_single_permissions (
			&auth_request, token->str, auth_service->service_name,
			auth_route->permissions_type, resource, auth_route->action
		);

		// perform request to auth service
		if (!auth_request_authentication (
			auth_service->auth_service_address, &auth_request
		)) {
			percepthor_single_authentication_internal (
				request, &auth_request, auth_route->permissions_type,
				resource, auth_route->action
			);

			retval = 0;
		}
	}

	#ifdef PERCEPTHOR_DEBUG
	else {
		cerver_log_error (
			"percepthor_single_authentication () "
			"Failed to get token from request's \"Authorization\" header!"
		);
	}
	#endif

	return retval;

}

static unsigned int percepthor_custom_internal_authentication_handler (
	const HttpRequest *request, const char *auth_service_address,
	const PercepthorAuthType auth_type, AuthRequest *auth_request
) {

	unsigned int retval = 1;

	// perform request to the auth service and handle token response
	if (!auth_request_authentication (auth_service_address, auth_request)) {
		PercepthorAuth *percepthor_auth = percepthor_auth_create (auth_type);

		// get token values from response's body
		if (!percepthor_auth_handle_response (
			percepthor_auth, auth_request->response
		)) {
			#ifdef PERCEPTHOR_DEBUG
			cerver_log_success ("Success auth!");
			#endif

			http_request_set_custom_data (
				(HttpRequest *) request, percepthor_auth
			);

			http_request_set_delete_custom_data (
				(HttpRequest *) request, percepthor_auth_delete
			);

			retval = 0;
		}
	}

	return retval;

}

static unsigned int percepthor_custom_service_authentication_handler (
	const HttpRequest *request, const char *auth_service_address, AuthRequest *auth_request
) {

	unsigned int retval = 1;

	// perform request to the auth service
	if (!auth_request_authentication (auth_service_address, auth_request)) {
		PercepthorAuth *percepthor_auth = (PercepthorAuth *) percepthor_auth_new ();

		// get actions mask from response's body
		if (!percepthor_auth_handle_response (
			percepthor_auth, auth_request->response
		)) {
			#ifdef PERCEPTHOR_DEBUG
			cerver_log_success ("Success auth!");
			#endif

			http_request_set_custom_data (
				(HttpRequest *) request, percepthor_auth
			);

			http_request_set_delete_custom_data (
				(HttpRequest *) request, percepthor_auth_delete
			);

			retval = 0;
		}
	}

	return retval;

}

static unsigned int percepthor_custom_permissions_authentication_handler (
	const HttpRequest *request, const char *auth_service_address,
	AuthRequest *auth_request, const PermissionsType permissions_type
) {

	unsigned int retval = 1;

	// perform request to the auth service
	if (!auth_request_authentication (auth_service_address, auth_request)) {
		PercepthorAuth *percepthor_auth = percepthor_auth_create (PERCEPTHOR_AUTH_TYPE_PERMISSIONS);

		percepthor_auth->scope = PERCEPTHOR_AUTH_SCOPE_MANAGEMENT;
		percepthor_auth->permissions_type = permissions_type;

		// get resources permissions from response's body
		if (!percepthor_auth_handle_response (
			percepthor_auth, auth_request->response
		)) {
			#ifdef PERCEPTHOR_DEBUG
			cerver_log_success ("Success auth!");
			#endif

			http_request_set_custom_data (
				(HttpRequest *) request, percepthor_auth
			);

			http_request_set_delete_custom_data (
				(HttpRequest *) request, percepthor_auth_delete
			);

			retval = 0;
		}
	}

	return retval;

}

unsigned int percepthor_custom_authentication_handler (
	const HttpReceive *http_receive, const HttpRequest *request
) {

	unsigned int retval = 1;

	// get the token from the request's headers
	const String *token = http_request_get_header (
		request, HTTP_HEADER_AUTHORIZATION
	);

	if (token) {
		const AuthService *auth_service = (
			const AuthService *
		) http_receive->http_cerver->custom_data;

		const AuthRoute *auth_route = (
			const AuthRoute *
		) http_receive->route->custom_data;

		AuthRequest auth_request = { 0 };

		switch (auth_route->auth_type) {
			case PERCEPTHOR_AUTH_TYPE_NONE: break;

			case PERCEPTHOR_AUTH_TYPE_TOKEN:
				auth_request_create (
					&auth_request, token->str, auth_service->service_name
				);

				retval = percepthor_custom_internal_authentication_handler (
					request, auth_service->auth_service_address,
					PERCEPTHOR_AUTH_TYPE_TOKEN, &auth_request
				);
				break;

			case PERCEPTHOR_AUTH_TYPE_ACTION:
				auth_request_create_action (
					&auth_request, token->str,
					auth_service->service_name, auth_route->action
				);

				retval = percepthor_custom_internal_authentication_handler (
					request, auth_service->auth_service_address,
					PERCEPTHOR_AUTH_TYPE_ACTION, &auth_request
				);
				break;

			case PERCEPTHOR_AUTH_TYPE_ROLE:
				auth_request_create_role (
					&auth_request, token->str, auth_service->service_name,
					auth_route->action, auth_route->role
				);

				retval = percepthor_custom_internal_authentication_handler (
					request, auth_service->auth_service_address,
					PERCEPTHOR_AUTH_TYPE_ROLE, &auth_request
				);
				break;

			case PERCEPTHOR_AUTH_TYPE_SERVICE:
				auth_request_create_service (
					&auth_request, token->str,
					auth_service->service_name, auth_service->service_id
				);

				retval = percepthor_custom_service_authentication_handler (
					request, auth_service->auth_service_address, &auth_request
				);
				break;

			case PERCEPTHOR_AUTH_TYPE_PERMISSIONS:
				auth_request_create_management_permissions (
					&auth_request, token->str, auth_service->service_name,
					auth_route->permissions_type,
					auth_route->permissions_action_len ? auth_route->permissions_action : NULL
				);

				retval = percepthor_custom_permissions_authentication_handler (
					request, auth_service->auth_service_address,
					&auth_request, auth_route->permissions_type
				);
				break;

			case PERCEPTHOR_AUTH_TYPE_MULTIPLE: break;
			case PERCEPTHOR_AUTH_TYPE_COMPLETE: break;

			default: break;
		}
	}

	#ifdef PERCEPTHOR_DEBUG
	else {
		cerver_log_error (
			"percepthor_custom_auth () "
			"Failed to get token from request's \"Authorization\" header!"
		);
	}
	#endif

	return retval;

}
