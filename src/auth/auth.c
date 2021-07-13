#include <stdlib.h>
#include <string.h>

#include <cerver/http/http.h>
#include <cerver/http/request.h>

#include <cerver/http/json/json.h>

#ifdef PERCEPTHOR_DEBUG
#include <cerver/utils/log.h>
#endif

#include "auth/auth.h"
#include "auth/requests.h"
#include "auth/service.h"

static void *percepthor_auth_new (void) {

	PercepthorAuth *auth = (PercepthorAuth *) malloc (sizeof (PercepthorAuth));
	if (auth) {
		(void) memset (auth, 0, sizeof (PercepthorAuth));
	}

	return auth;

}

static void percepthor_auth_delete (void *auth_ptr) {

	if (auth_ptr) {
		free (auth_ptr);
	}

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
