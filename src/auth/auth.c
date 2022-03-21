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
#include "auth/service.h"

const char *percepthor_auth_type_to_string (const PercepthorAuthType type) {

	switch (type) {
		#define XX(num, name, string) case PERCEPTHOR_AUTH_TYPE_##name: return #string;
		PERCEPTHOR_AUTH_TYPE_MAP(XX)
		#undef XX
	}

	return percepthor_auth_type_to_string (PERCEPTHOR_AUTH_TYPE_NONE);

}

static PercepthorAuth *percepthor_auth_new (void) {

	PercepthorAuth *auth = (PercepthorAuth *) malloc (sizeof (PercepthorAuth));
	if (auth) {
		(void) memset (auth, 0, sizeof (PercepthorAuth));

		auth->type = PERCEPTHOR_AUTH_TYPE_NONE;

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

const char *percepthor_auth_get_organization (
	const PercepthorAuth *percepthor_auth
) {

	return percepthor_auth->organization;

}

const char *percepthor_auth_get_project (
	const PercepthorAuth *percepthor_auth
) {

	return percepthor_auth->project;

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

PercepthorAuth *percepthor_auth_create (const PercepthorAuthType type) {

	PercepthorAuth *percepthor_auth = percepthor_auth_new ();
	if (percepthor_auth) {
		percepthor_auth->type = type;

		switch (percepthor_auth->type) {
			case PERCEPTHOR_AUTH_TYPE_NONE: break;

			case PERCEPTHOR_AUTH_TYPE_SINGLE: break;

			case PERCEPTHOR_AUTH_TYPE_MANAGEMENT:
				percepthor_auth->permissions = dlist_init (permissions_delete, NULL);
				break;

			case PERCEPTHOR_AUTH_TYPE_TOKEN: break;

			default: break;
		}
	}

	return percepthor_auth;

}

static void percepthor_single_authentication_internal (
	const HttpRequest *request,
	const char *organization, const char *action
) {

	#ifdef PERCEPTHOR_DEBUG
	cerver_log_success ("Success auth!");
	#endif

	PercepthorAuth *percepthor_auth = percepthor_auth_create (PERCEPTHOR_AUTH_TYPE_SINGLE);

	(void) strncpy (percepthor_auth->organization, organization, AUTH_ORGANIZATION_SIZE - 1);
	(void) strncpy (percepthor_auth->action, action, AUTH_ACTION_SIZE - 1);

	http_request_set_custom_data (
		(HttpRequest *) request, percepthor_auth
	);

	http_request_set_delete_custom_data (
		(HttpRequest *) request, percepthor_auth_delete
	);

}

unsigned int percepthor_single_authentication (
	const HttpReceive *http_receive, const HttpRequest *request,
	const char *organization, const char *action
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
		auth_request_create_single (
			&auth_request, token->str,
			organization, action	
		);

		// perform request to auth service
		if (!auth_request_authentication (
			auth_service->auth_service_address,
			&auth_request
		)) {
			percepthor_single_authentication_internal (
				request,
				organization, action
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

static inline void percepthor_management_authentication_parse_single_organization (
	Permissions *permissions, json_t *json_object
) {

	const char *key = NULL;
	json_t *value = NULL;
	if (json_typeof (json_object) == JSON_OBJECT) {
		json_object_foreach (json_object, key, value) {
			if (!strcmp (key, "_id")) {
				(void) strncpy (
					permissions->organization,
					json_string_value (value),
					AUTH_ORGANIZATION_SIZE - 1
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

static inline void percepthor_management_authentication_parse_organizations (
	PercepthorAuth *percepthor_auth, json_t *organizations_array
) {

	size_t n_organizations = json_array_size (organizations_array);
	json_t *json_object = NULL;
	for (size_t i = 0; i < n_organizations; i++) {
		json_object = json_array_get (organizations_array, i);
		if (json_object) {
			Permissions *permissions = permissions_create ();
			if (permissions) {
				percepthor_management_authentication_parse_single_organization (
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
			if (!strcmp (key, "organizations")) {
				if (json_typeof (value) == JSON_ARRAY) {
					percepthor_management_authentication_parse_organizations (
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
			"percepthor_custom_auth () - json error on line %d: %s\n",
			json_error.line, json_error.text
		);
	}
	#endif

	return retval;

}

static unsigned int percepthor_management_authentication_internal (
	const HttpRequest *request, AuthRequest *auth_request
) {

	unsigned int retval = 1;

	PercepthorAuth *percepthor_auth = percepthor_auth_create (PERCEPTHOR_AUTH_TYPE_MANAGEMENT);

	// get actions mask from response's body
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

	return retval;

}

unsigned int percepthor_management_authentication (
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
		) http_cerver_get_custom_data (
			http_receive->http_cerver
		);

		AuthRequest auth_request = { 0 };
		auth_request_create_management (
			&auth_request, token->str
		);

		// perform request to auth service
		if (!auth_request_authentication (
			auth_service->auth_service_address,
			&auth_request
		)) {
			percepthor_management_authentication_internal (
				request, &auth_request
			);

			retval = 0;
		}
	}

	#ifdef PERCEPTHOR_DEBUG
	else {
		cerver_log_error (
			"percepthor_management_authentication () "
			"Failed to get token from request's \"Authorization\" header!"
		);
	}
	#endif

	return retval;

}

static void percepthor_custom_authentication_parse_json (
	json_t *json_body,
	const char **mask
) {

	const char *key = NULL;
	json_t *value = NULL;
	if (json_typeof (json_body) == JSON_OBJECT) {
		json_object_foreach (json_body, key, value) {
			if (!strcmp (key, "mask")) {
				*mask = json_string_value (value);
				#ifdef PERCEPTHOR_DEBUG
				(void) printf ("mask: \"%s\"\n", *mask);
				#endif
			}
		}
	}

}

static unsigned int percepthor_custom_authentication_handle_response (
	PercepthorAuth *percepthor_auth, const char *response
) {

	unsigned int retval = 1;

	const char *mask = NULL;

	json_error_t json_error =  { 0 };
	json_t *json_body = json_loads (response, 0, &json_error);
	if (json_body) {
		percepthor_custom_authentication_parse_json (
			json_body,
			&mask
		);

		// validate required values
		if (mask) {
			percepthor_auth->mask = (int64_t) atoll (mask);

			retval = 0;
		}

		#ifdef PERCEPTHOR_DEBUG
		else {
			cerver_log_error ("percepthor_custom_auth () - missing values!");
		}
		#endif

		json_decref (json_body);
	}

	#ifdef PERCEPTHOR_DEBUG
	else {
		cerver_log_error (
			"percepthor_custom_auth () - json error on line %d: %s\n",
			json_error.line, json_error.text
		);
	}
	#endif

	return retval;

}

static unsigned int percepthor_custom_authentication_handler_internal (
	const HttpRequest *request,
	AuthRequest *auth_request
) {

	unsigned int retval = 1;

	// TODO: create pool
	PercepthorAuth *percepthor_auth = (PercepthorAuth *) percepthor_auth_new ();

	// get actions mask from response's body
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

	return retval;

}

unsigned int percepthor_custom_authentication_handler (
	const HttpReceive *http_receive,
	const HttpRequest *request
) {

	unsigned int retval = 1;

	// get the token from the request's headers
	const String *api_key = http_request_get_header (
		request, HTTP_HEADER_AUTHORIZATION
	);

	if (api_key) {
		const AuthService *auth_service = (
			const AuthService *
		) http_cerver_get_custom_data (
			http_receive->http_cerver
		);

		AuthRequest auth_request = { 0 };
		auth_request_create (
			&auth_request,
			api_key->str,
			auth_service->service_id
		);

		// perform request to auth service
		// send token in "Authorization" header
		// send service's id in requests body
		if (!auth_request_authentication (
			auth_service->auth_service_address,
			&auth_request
		)) {
			retval = percepthor_custom_authentication_handler_internal (
				request, &auth_request
			);
		}
	}

	#ifdef PERCEPTHOR_DEBUG
	else {
		cerver_log_error (
			"percepthor_custom_auth () "
			"Failed to get API Key from request's \"Authorization\" header!"
		);
	}
	#endif

	return retval;

}
