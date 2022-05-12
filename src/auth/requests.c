#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>

#ifdef PERCEPTHOR_DEBUG
#include <cerver/utils/log.h>
#endif

#include "auth/auth.h"
#include "auth/permissions.h"
#include "auth/requests.h"

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

void auth_request_create (
	AuthRequest *auth_request, const char *token, const char *source
) {

	// prepare the request
	(void) snprintf (
		auth_request->auth_header, AUTH_HEADER_SIZE,
		"Authorization: %s", token
	);

	(void) snprintf (
		auth_request->body, AUTH_REQUEST_SIZE,
		"{ \"type\": %d, \"source\": \"%s\" }",
		PERCEPTHOR_AUTH_TYPE_TOKEN, source
	);

	auth_request->body_len = strlen (auth_request->body);

}

void auth_request_create_action (
	AuthRequest *auth_request, const char *token,
	const char *source, const char *action
) {

	// prepare the request
	(void) snprintf (
		auth_request->auth_header, AUTH_HEADER_SIZE,
		"Authorization: %s", token
	);

	(void) snprintf (
		auth_request->body, AUTH_REQUEST_SIZE,
		"{ \"type\": %d, \"source\": \"%s\", \"action\": \"%s\" }",
		PERCEPTHOR_AUTH_TYPE_ACTION, source, action
	);

	auth_request->body_len = strlen (auth_request->body);

}

void auth_request_create_role (
	AuthRequest *auth_request,
	const char *token, const char *source,
	const char *action, const char *role
) {

	// prepare the request
	(void) snprintf (
		auth_request->auth_header, AUTH_HEADER_SIZE,
		"Authorization: %s", token
	);

	if (action && role) {
		(void) snprintf (
			auth_request->body, AUTH_REQUEST_SIZE,
			"{ \"type\": %d, \"source\": \"%s\", \"action\": \"%s\", \"role\": \"%s\" }",
			PERCEPTHOR_AUTH_TYPE_ROLE, source, action, role
		);
	}

	else {
		(void) snprintf (
			auth_request->body, AUTH_REQUEST_SIZE,
			"{ \"type\": %d, \"action\": None, \"role\": \"%s\" }",
			PERCEPTHOR_AUTH_TYPE_ROLE, role
		);
	}

	auth_request->body_len = strlen (auth_request->body);

}

void auth_request_create_service (
	AuthRequest *auth_request, const char *token,
	const char *source, const char *service
) {

	// prepare the request
	(void) snprintf (
		auth_request->auth_header, AUTH_HEADER_SIZE,
		"Authorization: %s", token
	);

	(void) snprintf (
		auth_request->body, AUTH_REQUEST_SIZE,
		"{ \"type\": %d, \"source\": \"%s\", \"service\": \"%s\" }",
		PERCEPTHOR_AUTH_TYPE_SERVICE, source, service
	);

	auth_request->body_len = strlen (auth_request->body);

}

void auth_request_create_single_permissions (
	AuthRequest *auth_request,
	const char *token, const char *source,
	const PermissionsType permissions_type,
	const char *resource, const char *permissions_action
) {
	
	// prepare the request
	(void) snprintf (
		auth_request->auth_header, AUTH_HEADER_SIZE,
		"Authorization: %s", token
	);

	(void) snprintf (
		auth_request->body, AUTH_REQUEST_SIZE,
		"{ \"type\": %d, \"source\": \"%s\", \"scope\": %d, \"permissions_type\": %u, \"resource\": \"%s\", \"action\": \"%s\" }",
		PERCEPTHOR_AUTH_TYPE_PERMISSIONS, source,
		PERCEPTHOR_AUTH_SCOPE_SINGLE, permissions_type,
		resource, permissions_action
	);

	auth_request->body_len = strlen (auth_request->body);

}

void auth_request_create_management_permissions (
	AuthRequest *auth_request, const char *token, const char *source,
	const PermissionsType permissions_type, const char *permissions_action
) {

	// prepare the request
	(void) snprintf (
		auth_request->auth_header, AUTH_HEADER_SIZE,
		"Authorization: %s", token
	);

	if (permissions_action) {
		(void) snprintf (
			auth_request->body, AUTH_REQUEST_SIZE,
			"{ \"type\": %d, \"source\": \"%s\", \"scope\": %d, \"permissions_type\": %u, \"action\": \"%s\" }",
			PERCEPTHOR_AUTH_TYPE_PERMISSIONS, source,
			PERCEPTHOR_AUTH_SCOPE_MANAGEMENT, permissions_type,
			permissions_action
		);
	}

	else {
		(void) snprintf (
			auth_request->body, AUTH_REQUEST_SIZE,
			"{ \"type\": %d, \"scope\": %d, \"permissions_type\": %u }",
			PERCEPTHOR_AUTH_TYPE_PERMISSIONS, PERCEPTHOR_AUTH_SCOPE_MANAGEMENT, permissions_type
		);
	}

	auth_request->body_len = strlen (auth_request->body);

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

	RequestResult result = REQUEST_RESULT_NONE;

	CURL *curl = curl_easy_init ();
	if (curl) {
		curl_easy_setopt (curl, CURLOPT_URL, auth_service_address);

		// add custom "Authorization" header
		struct curl_slist *headers = NULL;

		headers = curl_slist_append (headers, auth_request->auth_header);

		curl_easy_setopt (curl, CURLOPT_HTTPHEADER, headers);

		curl_easy_setopt (curl, CURLOPT_POSTFIELDS, auth_request->body);
		curl_easy_setopt (curl, CURLOPT_POSTFIELDSIZE, auth_request->body_len);

		curl_easy_setopt (
			curl, CURLOPT_WRITEFUNCTION,
			auth_request_authentication_write_cb
		);

		curl_easy_setopt (curl, CURLOPT_WRITEDATA, auth_request);

		result = auth_request_perform (curl);

		curl_slist_free_all (headers);

		curl_easy_cleanup (curl);
	}

	return result;

}
