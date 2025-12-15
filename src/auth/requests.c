#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <pthread.h>

#include <curl/curl.h>

#include <cerver/http/json/json.h>

#ifdef PERCEPTHOR_DEBUG
#include <cerver/utils/log.h>
#endif

#include "auth/auth.h"
#include "auth/permissions.h"
#include "auth/requests.h"

static const char *auth_header_prefix = { "Authorization: " };

// curl_easy_init () calls curl_global_init () implicitly when needed,
// which is not thread safe, so the global init is done exactly once
static pthread_once_t auth_request_curl_once = PTHREAD_ONCE_INIT;

static void auth_request_curl_global_init (void) {

	(void) curl_global_init (CURL_GLOBAL_DEFAULT);

}

const char *request_result_to_string (const RequestResult type) {

	switch (type) {
		#define XX(num, name, string) case REQUEST_RESULT_##name: return #string;
		REQUEST_RESULT_MAP(XX)
		#undef XX
	}

	return request_result_to_string (REQUEST_RESULT_NONE);

}

void *auth_request_new (void) {

	AuthRequest *request = (AuthRequest *) malloc (sizeof (AuthRequest));
	if (request) {
		(void) memset (request, 0, sizeof (AuthRequest));
	}

	return request;

}

void auth_request_delete (void *request_ptr) {

	if (request_ptr) {
		free (request_ptr);
	}

}

// a request is only valid when its header and its body were complete,
// a truncated one is never sent to the auth service
bool auth_request_is_valid (const AuthRequest *auth_request) {

	return auth_request
		&& (auth_request->auth_header_len > 0)
		&& (auth_request->body_len > 0);

}

static void auth_request_header (AuthRequest *auth_request, const char *token) {

	if (!auth_request) return;

	auth_request->auth_header_len = 0;

	if (token) {
		const int written = snprintf (
			auth_request->auth_header, AUTH_HEADER_SIZE,
			"%s%s", auth_header_prefix, token
		);

		if ((written > 0) && (written < AUTH_HEADER_SIZE)) {
			auth_request->auth_header_len = (size_t) written;
		}
	}

}

// adds a string to the body; a missing or empty value is left out
static bool auth_request_body_add_string (
	json_t *body, const char *key, const char *value
) {

	bool added = true;

	if (value && value[0]) {
		// json_string () fails on a value that is not valid UTF-8
		added = !json_object_set_new (body, key, json_string (value));
	}

	return added;

}

static bool auth_request_body_add_integer (
	json_t *body, const char *key, const json_int_t value
) {

	return !json_object_set_new (body, key, json_integer (value));

}

// the base of every body, with the auth type and the source service
static json_t *auth_request_body_create (
	const PercepthorAuthType type, const char *source, bool *valid
) {

	json_t *body = json_object ();
	if (body) {
		*valid = auth_request_body_add_integer (body, "type", type)
			&& auth_request_body_add_string (body, "source", source);
	}

	else {
		*valid = false;
	}

	return body;

}

// the values are escaped by the serializer, so a quote in a resource
// can not add or overwrite a field of the request to the auth service
static void auth_request_body_dump (
	AuthRequest *auth_request, json_t *body, const bool valid
) {

	if (!auth_request) {
		if (body) json_decref (body);

		return;
	}

	auth_request->body_len = 0;
	auth_request->body[0] = '\0';

	if (body && valid) {
		const size_t needed = json_dumpb (
			body, auth_request->body, AUTH_REQUEST_SIZE - 1, JSON_COMPACT
		);

		if ((needed > 0) && (needed < AUTH_REQUEST_SIZE)) {
			auth_request->body[needed] = '\0';
			auth_request->body_len = needed;
		}

		else {
			auth_request->body[0] = '\0';

			#ifdef PERCEPTHOR_DEBUG
			cerver_log_error (
				"auth_request_body_dump () - "
				"a body of %zu bytes does not fit in %d bytes!",
				needed, AUTH_REQUEST_SIZE
			);
			#endif
		}
	}

	if (body) json_decref (body);

}

void auth_request_create (
	AuthRequest *auth_request, const char *token, const char *source
) {

	auth_request_header (auth_request, token);

	bool valid = false;
	json_t *body = auth_request_body_create (PERCEPTHOR_AUTH_TYPE_TOKEN, source, &valid);

	auth_request_body_dump (auth_request, body, valid);

}

void auth_request_create_action (
	AuthRequest *auth_request, const char *token,
	const char *source, const char *action
) {

	auth_request_header (auth_request, token);

	bool valid = false;
	json_t *body = auth_request_body_create (PERCEPTHOR_AUTH_TYPE_ACTION, source, &valid);
	if (body) {
		valid = valid && auth_request_body_add_string (body, "action", action);
	}

	auth_request_body_dump (auth_request, body, valid);

}

// the action of a role is optional, the role is required
void auth_request_create_role (
	AuthRequest *auth_request,
	const char *token, const char *source,
	const char *action, const char *role
) {

	auth_request_header (auth_request, token);

	bool valid = false;
	json_t *body = auth_request_body_create (PERCEPTHOR_AUTH_TYPE_ROLE, source, &valid);
	if (body) {
		valid = valid
			&& auth_request_body_add_string (body, "action", action)
			&& auth_request_body_add_string (body, "role", role);
	}

	auth_request_body_dump (auth_request, body, valid);

}

void auth_request_create_service (
	AuthRequest *auth_request, const char *token,
	const char *source, const char *service
) {

	auth_request_header (auth_request, token);

	bool valid = false;
	json_t *body = auth_request_body_create (PERCEPTHOR_AUTH_TYPE_SERVICE, source, &valid);
	if (body) {
		valid = valid && auth_request_body_add_string (body, "service", service);
	}

	auth_request_body_dump (auth_request, body, valid);

}

void auth_request_create_single_permissions (
	AuthRequest *auth_request,
	const char *token, const char *source,
	const PermissionsType permissions_type,
	const char *resource, const char *permissions_action
) {

	auth_request_header (auth_request, token);

	bool valid = false;
	json_t *body = auth_request_body_create (PERCEPTHOR_AUTH_TYPE_PERMISSIONS, source, &valid);
	if (body) {
		valid = valid
			&& auth_request_body_add_integer (body, "scope", PERCEPTHOR_AUTH_SCOPE_SINGLE)
			&& auth_request_body_add_integer (body, "permissions_type", permissions_type)
			&& auth_request_body_add_string (body, "resource", resource)
			&& auth_request_body_add_string (body, "action", permissions_action);
	}

	auth_request_body_dump (auth_request, body, valid);

}

void auth_request_create_management_permissions (
	AuthRequest *auth_request, const char *token, const char *source,
	const PermissionsType permissions_type, const char *permissions_action
) {

	auth_request_header (auth_request, token);

	bool valid = false;
	json_t *body = auth_request_body_create (PERCEPTHOR_AUTH_TYPE_PERMISSIONS, source, &valid);
	if (body) {
		valid = valid
			&& auth_request_body_add_integer (body, "scope", PERCEPTHOR_AUTH_SCOPE_MANAGEMENT)
			&& auth_request_body_add_integer (body, "permissions_type", permissions_type)
			&& auth_request_body_add_string (body, "action", permissions_action);
	}

	auth_request_body_dump (auth_request, body, valid);

}

static size_t auth_request_authentication_write_cb (
	void *contents, size_t size, size_t nmemb, void *auth_mem
) {

	size_t real_size = size * nmemb;

	AuthRequest *auth_request = (AuthRequest *) auth_mem;

	char *auth_response_mem = auth_request->response;
	(void) memcpy (&(auth_response_mem[auth_request->response_ptr]), contents, real_size);
	auth_request->response_ptr += real_size;
	auth_response_mem[auth_request->response_ptr] = 0;

	return real_size;

}

// the Authorization header, NULL when it could not be added: the list is never sent incomplete
static struct curl_slist *auth_request_headers_append (
	struct curl_slist *headers, const char *header
) {

	struct curl_slist *appended = curl_slist_append (headers, header);
	if (!appended) {
		curl_slist_free_all (headers);
	}

	return appended;

}

static struct curl_slist *auth_request_headers (const AuthRequest *auth_request) {

	return auth_request_headers_append (NULL, auth_request->auth_header);

}

static RequestResult auth_request_perform (CURL *curl) {

	RequestResult result = REQUEST_RESULT_NONE;

	CURLcode res = curl_easy_perform (curl);

	long http_code = 0;
	curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &http_code);

	if (res != CURLE_OK) {
		#ifdef PERCEPTHOR_DEBUG
		cerver_log_error (
			"auth_request_perform () failed: %s\n",
			curl_easy_strerror (res)
		);
		#endif

		result = REQUEST_RESULT_FAILED;
	}

	else if (http_code != 200) {
		#ifdef PERCEPTHOR_DEBUG
		cerver_log_error (
			"auth_request_perform () expected status 200 but got %ld instead!",
			http_code
		);
		#endif

		result = REQUEST_RESULT_BAD_STATUS;
	}

	return result;

}

RequestResult auth_request_authentication (
	const char *auth_service_address,
	AuthRequest *auth_request
) {

	RequestResult result = REQUEST_RESULT_FAILED;

	if (auth_service_address && auth_service_address[0] && auth_request_is_valid (auth_request)) {
		(void) pthread_once (&auth_request_curl_once, auth_request_curl_global_init);

		CURL *curl = curl_easy_init ();
		if (curl) {
			curl_easy_setopt (curl, CURLOPT_URL, auth_service_address);

			// this runs inside a multi threaded server:
			// never let curl use signals (SIGALRM) for its timeouts,
			// they interrupt the system calls of other threads (EINTR)
			curl_easy_setopt (curl, CURLOPT_NOSIGNAL, 1L);

			curl_easy_setopt (curl, CURLOPT_CONNECTTIMEOUT, (long) AUTH_REQUEST_CONNECT_TIMEOUT);
			curl_easy_setopt (curl, CURLOPT_TIMEOUT, (long) AUTH_REQUEST_TIMEOUT);

			struct curl_slist *headers = auth_request_headers (auth_request);
			if (headers) {
				curl_easy_setopt (curl, CURLOPT_HTTPHEADER, headers);

				curl_easy_setopt (curl, CURLOPT_POSTFIELDS, auth_request->body);
				curl_easy_setopt (curl, CURLOPT_POSTFIELDSIZE, (long) auth_request->body_len);

				curl_easy_setopt (
					curl, CURLOPT_WRITEFUNCTION,
					auth_request_authentication_write_cb
				);

				curl_easy_setopt (curl, CURLOPT_WRITEDATA, auth_request);

				result = auth_request_perform (curl);

				curl_slist_free_all (headers);
			}

			curl_easy_cleanup (curl);
		}
	}

	return result;

}
