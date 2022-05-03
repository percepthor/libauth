#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <cerver/collections/dlist.h>

#include <cerver/http/http.h>
#include <cerver/http/request.h>

#include <cerver/http/json/json.h>

#ifdef PERCEPTHOR_DEBUG
#include <cerver/utils/log.h>
#endif

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

const PercepthorAuthType percepthor_auth_get_type (
	const PercepthorAuth *percepthor_auth
) {

	return percepthor_auth->type;

}

const PercepthorAuthScope percepthor_auth_get_scope (
	const PercepthorAuth *percepthor_auth
) {

	return percepthor_auth->scope;

}

const char *percepthor_auth_get_resource (
	const PercepthorAuth *percepthor_auth
) {

	return percepthor_auth->resource;

}

const char *percepthor_auth_get_action (
	const PercepthorAuth *percepthor_auth
) {

	return percepthor_auth->action;

}

const bool percepthor_auth_get_admin (
	const PercepthorAuth *percepthor_auth
) {

	return percepthor_auth->super_admin;

}

static void percepthor_auth_set_admin (
	PercepthorAuth *percepthor_auth, const bool is_admin
) {

	percepthor_auth->super_admin = is_admin;

}

DoubleList *percepthor_auth_get_permissions (
	const PercepthorAuth *percepthor_auth
) {

	return percepthor_auth->permissions;

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

	if (percepthor_auth->next_permissions) {
		permissions = (const Permissions *) percepthor_auth->next_permissions->data;
		percepthor_auth->next_permissions = percepthor_auth->next_permissions->next;
	}

	return permissions;

}

const char *percepthor_auth_get_token_id (
	const PercepthorAuth *percepthor_auth
) {

	return percepthor_auth->token.id;

}

const PercepthorTokenType percepthor_auth_get_token_type (
	const PercepthorAuth *percepthor_auth
) {

	return percepthor_auth->token.type;

}

const char *percepthor_auth_get_token_organization (
	const PercepthorAuth *percepthor_auth
) {

	return percepthor_auth->token.organization;

}

const char *percepthor_auth_get_token_permissions (
	const PercepthorAuth *percepthor_auth
) {

	return percepthor_auth->token.permissions;

}

const char *percepthor_auth_get_token_role (
	const PercepthorAuth *percepthor_auth
) {

	return percepthor_auth->token.role;

}

const char *percepthor_auth_get_token_user (
	const PercepthorAuth *percepthor_auth
) {

	return percepthor_auth->token.user;

}

const char *percepthor_auth_get_token_username (
	const PercepthorAuth *percepthor_auth
) {

	return percepthor_auth->token.username;

}

const int64_t percepthor_auth_get_mask (
	const PercepthorAuth *percepthor_auth
) {

	return percepthor_auth->mask;

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
				percepthor_auth->permissions = dlist_init (permissions_delete, NULL);
				break;

			case PERCEPTHOR_AUTH_TYPE_MULTIPLE: break;
			case PERCEPTHOR_AUTH_TYPE_COMPLETE: break;

			default: break;
		}
	}

	return percepthor_auth;

}

void percepthor_auth_print_token (const PercepthorAuth *percepthor_auth) {

	percepthor_token_print (&percepthor_auth->token);

}

static inline void percepthor_custom_authentication_parse_token (
	AuthToken *token, json_t *json_object
) {

	const char *key = NULL;
	json_t *value = NULL;
	json_object_foreach (json_object, key, value) {
		if (!strcmp (key, "id")) {
			(void) snprintf (
				token->id, AUTH_ID_SIZE, "%s", json_string_value (value)
			);
		}

		else if (!strcmp (key, "t_type")) {
			token->type = (PercepthorTokenType) json_integer_value (value);
		}

		else if (!strcmp (key, "organization")) {
			(void) snprintf (
				token->organization, AUTH_ID_SIZE, "%s", json_string_value (value)
			);
		}

		else if (!strcmp (key, "permissions")) {
			(void) snprintf (
				token->permissions, AUTH_ID_SIZE, "%s", json_string_value (value)
			);
		}

		else if (!strcmp (key, "role")) {
			(void) snprintf (
				token->role, AUTH_ID_SIZE, "%s", json_string_value (value)
			);
		}

		else if (!strcmp (key, "user")) {
			(void) snprintf (
				token->user, AUTH_ID_SIZE, "%s", json_string_value (value)
			);
		}

		else if (!strcmp (key, "username")) {
			(void) snprintf (
				token->username, AUTH_TOKEN_USERNAME_SIZE, "%s", json_string_value (value)
			);
		}
	}

}

static void percepthor_single_authentication_internal (
	const HttpRequest *request, const PermissionsType permissions_type,
	const char *resource, const char *action
) {

	#ifdef PERCEPTHOR_DEBUG
	cerver_log_success ("Success auth!");
	#endif

	PercepthorAuth *percepthor_auth = percepthor_auth_create (PERCEPTHOR_AUTH_TYPE_PERMISSIONS);

	percepthor_auth->scope = PERCEPTHOR_AUTH_SCOPE_SINGLE;
	percepthor_auth->permissions_type = permissions_type;

	(void) snprintf (percepthor_auth->resource, AUTH_RESOURCE_SIZE, "%s", resource);
	(void) snprintf (percepthor_auth->action, AUTH_ACTION_SIZE, "%s", action);

	http_request_set_custom_data (
		(HttpRequest *) request, percepthor_auth
	);

	http_request_set_delete_custom_data (
		(HttpRequest *) request, percepthor_auth_delete
	);

}

unsigned int percepthor_single_authentication (
	const HttpReceive *http_receive, const HttpRequest *request,
	const PermissionsType permissions_type,
	const char *resource, const char *action
) {

	unsigned int retval = 1;

	// get the token from the request's headers
	const String *token = http_request_get_header (
		request, HTTP_HEADER_AUTHORIZATION
	);

	if (token) {
		const AuthService *auth_service = (
			const AuthService *
		) http_cerver_get_custom_data (
			http_receive->http_cerver
		);

		AuthRequest auth_request = { 0 };
		auth_request_create_single_permissions (
			&auth_request, token->str,
			permissions_type, resource, action
		);

		// perform request to auth service
		if (!auth_request_authentication (
			auth_service->auth_service_address, &auth_request
		)) {
			percepthor_single_authentication_internal (
				request, permissions_type, resource, action
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

static void percepthor_custom_authentication_parse_json (
	PercepthorAuth *percepthor_auth, json_t *json_body
) {

	const char *key = NULL;
	json_t *value = NULL;
	if (json_typeof (json_body) == JSON_OBJECT) {
		json_object_foreach (json_body, key, value) {
			if (!strcmp (key, "token")) {
				if (json_typeof (value) == JSON_OBJECT) {
					percepthor_custom_authentication_parse_token (
						&percepthor_auth->token, value
					);
				}
			}
		}
	}

}

static unsigned int percepthor_custom_authentication_handle_response (
	PercepthorAuth *percepthor_auth, const char *response
) {

	unsigned int retval = 1;

	json_error_t json_error =  { 0 };
	json_t *json_body = json_loads (response, 0, &json_error);
	if (json_body) {
		percepthor_custom_authentication_parse_json (percepthor_auth, json_body);

		json_decref (json_body);

		retval = 0;
	}

	#ifdef PERCEPTHOR_DEBUG
	else {
		cerver_log_error (
			"percepthor_custom_authentication_handle_response () - json error on line %d: %s\n",
			json_error.line, json_error.text
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
		if (!percepthor_custom_authentication_handle_response (
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

static void percepthor_custom_service_authentication_parse_json (
	PercepthorAuth *percepthor_auth, json_t *json_body
) {

	const char *key = NULL;
	json_t *value = NULL;
	if (json_typeof (json_body) == JSON_OBJECT) {
		json_object_foreach (json_body, key, value) {
			if (!strcmp (key, "token")) {
				if (json_typeof (value) == JSON_OBJECT) {
					percepthor_custom_authentication_parse_token (
						&percepthor_auth->token, value
					);
				}
			}

			else if (!strcmp (key, "mask")) {
				percepthor_auth->mask = (int64_t) atoll (json_string_value (value));
				#ifdef PERCEPTHOR_DEBUG
				(void) printf ("mask: %ld\n", percepthor_auth->mask);
				#endif
			}
		}
	}

}

static unsigned int percepthor_custom_service_authentication_handle_response (
	PercepthorAuth *percepthor_auth, const char *response
) {

	unsigned int retval = 1;

	json_error_t json_error =  { 0 };
	json_t *json_body = json_loads (response, 0, &json_error);
	if (json_body) {
		percepthor_custom_service_authentication_parse_json (
			percepthor_auth, json_body
		);

		json_decref (json_body);

		retval = 0;
	}

	#ifdef PERCEPTHOR_DEBUG
	else {
		cerver_log_error (
			"percepthor_custom_service_authentication_handle_response () - json error on line %d: %s\n",
			json_error.line, json_error.text
		);
	}
	#endif

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
		if (!percepthor_custom_service_authentication_handle_response (
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

static inline void percepthor_management_authentication_parse_single_resource (
	Permissions *permissions, json_t *json_object
) {

	const char *key = NULL;
	json_t *value = NULL;
	if (json_typeof (json_object) == JSON_OBJECT) {
		json_object_foreach (json_object, key, value) {
			if (!strcmp (key, "_id")) {
				(void) snprintf (
					permissions->resource, AUTH_RESOURCE_SIZE,
					"%s", json_string_value (value)
				);
			}

			else if (!strcmp (key, "actions")) {
				size_t n_actions = json_array_size (value);
				for (size_t i = 0; i < n_actions; i++) {
					(void) dlist_insert_after_unsafe (
						permissions->actions,
						dlist_end (permissions->actions),
						permissions_action_create (
							json_string_value (json_array_get (value, i))
						)
					);
				}
			}
		}
	}

}

static inline void percepthor_management_authentication_parse_resources (
	PercepthorAuth *percepthor_auth, json_t *resources_array
) {

	size_t n_resources = json_array_size (resources_array);
	json_t *json_object = NULL;
	for (size_t i = 0; i < n_resources; i++) {
		json_object = json_array_get (resources_array, i);
		if (json_object) {
			Permissions *permissions = permissions_create ();
			if (permissions) {
				percepthor_management_authentication_parse_single_resource (
					permissions, json_object
				);

				(void) dlist_insert_after_unsafe (
					percepthor_auth->permissions,
					dlist_end (percepthor_auth->permissions),
					permissions
				);
			}
		}
	}

}

static inline void percepthor_management_authentication_parse_json (
	PercepthorAuth *percepthor_auth, json_t *json_body
) {

	const char *key = NULL;
	json_t *value = NULL;
	if (json_typeof (json_body) == JSON_OBJECT) {
		json_object_foreach (json_body, key, value) {
			if (!strcmp (key, "token")) {
				if (json_typeof (value) == JSON_OBJECT) {
					percepthor_custom_authentication_parse_token (
						&percepthor_auth->token, value
					);
				}
			}

			else if (!strcmp (key, "resources")) {
				if (json_typeof (value) == JSON_ARRAY) {
					percepthor_management_authentication_parse_resources (
						percepthor_auth, value
					);
				}
			}

			else if (!strcmp (key, "admin")) {
				percepthor_auth_set_admin (percepthor_auth, json_boolean_value (value));
			}
		}
	}

}

static unsigned int percepthor_management_authentication_handle_response (
	PercepthorAuth *percepthor_auth, const char *response
) {

	unsigned int retval = 1;

	json_error_t json_error =  { 0 };
	json_t *json_body = json_loads (response, 0, &json_error);
	if (json_body) {
		percepthor_management_authentication_parse_json (percepthor_auth, json_body);

		json_decref (json_body);

		retval = 0;
	}

	#ifdef PERCEPTHOR_DEBUG
	else {
		cerver_log_error (
			"percepthor_management_authentication_handle_response () - json error on line %d: %s\n",
			json_error.line, json_error.text
		);
	}
	#endif

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
		if (!percepthor_management_authentication_handle_response (
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
				auth_request_create (&auth_request, token->str);

				retval = percepthor_custom_internal_authentication_handler (
					request, auth_service->auth_service_address,
					PERCEPTHOR_AUTH_TYPE_TOKEN, &auth_request
				);
				break;

			case PERCEPTHOR_AUTH_TYPE_ACTION:
				auth_request_create_action (&auth_request, token->str, auth_route->action);

				retval = percepthor_custom_internal_authentication_handler (
					request, auth_service->auth_service_address,
					PERCEPTHOR_AUTH_TYPE_ACTION, &auth_request
				);
				break;

			case PERCEPTHOR_AUTH_TYPE_ROLE:
				auth_request_create_role (&auth_request, token->str, auth_route->action, auth_route->role);

				retval = percepthor_custom_internal_authentication_handler (
					request, auth_service->auth_service_address,
					PERCEPTHOR_AUTH_TYPE_ROLE, &auth_request
				);
				break;

			case PERCEPTHOR_AUTH_TYPE_SERVICE:
				auth_request_create_service (&auth_request, token->str, auth_service->service_id);

				retval = percepthor_custom_service_authentication_handler (
					request, auth_service->auth_service_address, &auth_request
				);
				break;

			case PERCEPTHOR_AUTH_TYPE_PERMISSIONS:
				auth_request_create_management_permissions (
					&auth_request, token->str, auth_route->permissions_type,
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
