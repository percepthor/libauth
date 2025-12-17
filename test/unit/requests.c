#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <cerver/http/json/json.h>

#include <auth/auth.h>
#include <auth/permissions.h>
#include <auth/requests.h>

#include "test.h"

// the requests to the auth service, read back as json

// bugs this suite fixed:
// - the values were written into the json with "%s", so a quote in a resource
//   added fields to the request: "\", \"scope\": 0, \"x\": \"" turned a single
//   permissions check into one the auth service answered without checking anything
// - a body or a header longer than its buffer was truncated and sent anyway
// - a role without an action sent "action": None, without the source
// - an empty action was sent as "", which the auth service rejects as missing
// - the X-Forwarded-For of a link local IPv6 client with its zone did not fit and was not sent
// - a single permissions route with a resource and an action of 256 bytes did not fit the body
// - the private builders dereferenced a NULL request

#define TEST_REQUESTS_TOKEN			"Bearer test-token"
#define TEST_REQUESTS_SOURCE		"tickets"
#define TEST_REQUESTS_ACTION		"tickets.create"
#define TEST_REQUESTS_ROLE			"admin"
#define TEST_REQUESTS_SERVICE		"507f1f77bcf86cd799439011"
#define TEST_REQUESTS_RESOURCE		"507f1f77bcf86cd799439012"

#define TEST_REQUESTS_LONG_SIZE		2048

// a resource that does not fit the body of a request
#define TEST_REQUESTS_BODY_SIZE		(AUTH_REQUEST_SIZE * 2)

// the longest address that cerver gives to a request: an IPv6 with the zone of its interface
#define TEST_REQUESTS_ZONED_ADDRESS	"ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255%interfacename15"

// a character that the serializer escapes as \u0001, six bytes for one
#define TEST_REQUESTS_ESCAPED		'\x01'

static const char *injected_resource = {
	TEST_REQUESTS_RESOURCE "\", \"scope\": 0, \"x\": \""
};

static json_t *test_requests_body (const AuthRequest *auth_request) {

	test_check_true (auth_request_is_valid (auth_request));
	test_check_unsigned_eq (auth_request->body_len, strlen (auth_request->body), NULL);

	json_error_t error = { 0 };
	json_t *body = json_loads (auth_request->body, 0, &error);
	test_check (body != NULL, auth_request->body);
	test_check_true (json_is_object (body));

	return body;

}

static void test_requests_check_integer (const json_t *body, const char *key, const json_int_t expected) {

	const json_t *value = json_object_get (body, key);
	test_check (json_is_integer (value), key);
	test_check_long_int_eq (json_integer_value (value), expected, key);

}

static void test_requests_check_string (const json_t *body, const char *key, const char *expected) {

	const json_t *value = json_object_get (body, key);
	test_check (json_is_string (value), key);
	test_check_str_eq (json_string_value (value), expected, key);

}

static void test_requests_check_header (const AuthRequest *auth_request) {

	test_check_str_eq (auth_request->auth_header, "Authorization: " TEST_REQUESTS_TOKEN, NULL);
	test_check_unsigned_eq (auth_request->auth_header_len, strlen (auth_request->auth_header), NULL);

}

static void test_requests_result (void) {

	test_check_str_eq (request_result_to_string (REQUEST_RESULT_NONE), "None", NULL);
	test_check_str_eq (request_result_to_string (REQUEST_RESULT_FAILED), "Failed", NULL);
	test_check_str_eq (request_result_to_string (REQUEST_RESULT_BAD_STATUS), "Bad Status", NULL);
	test_check_str_eq (request_result_to_string ((RequestResult) 64), "None", NULL);

}

static void test_requests_new (void) {

	AuthRequest *auth_request = (AuthRequest *) auth_request_new ();
	test_check_ptr (auth_request);
	test_check_false (auth_request_is_valid (auth_request));
	auth_request_delete (auth_request);

	auth_request_delete (NULL);
	test_check_false (auth_request_is_valid (NULL));

}

static void test_requests_token (void) {

	AuthRequest auth_request = { 0 };
	auth_request_create (&auth_request, TEST_REQUESTS_TOKEN, TEST_REQUESTS_SOURCE);

	test_requests_check_header (&auth_request);

	json_t *body = test_requests_body (&auth_request);
	test_requests_check_integer (body, "type", PERCEPTHOR_AUTH_TYPE_TOKEN);
	test_requests_check_string (body, "source", TEST_REQUESTS_SOURCE);
	test_check_unsigned_eq (json_object_size (body), 2, NULL);
	json_decref (body);

}

static void test_requests_action (void) {

	AuthRequest auth_request = { 0 };
	auth_request_create_action (&auth_request, TEST_REQUESTS_TOKEN, TEST_REQUESTS_SOURCE, TEST_REQUESTS_ACTION);

	test_requests_check_header (&auth_request);

	json_t *body = test_requests_body (&auth_request);
	test_requests_check_integer (body, "type", PERCEPTHOR_AUTH_TYPE_ACTION);
	test_requests_check_string (body, "source", TEST_REQUESTS_SOURCE);
	test_requests_check_string (body, "action", TEST_REQUESTS_ACTION);
	json_decref (body);

}

static void test_requests_role (void) {

	AuthRequest auth_request = { 0 };
	auth_request_create_role (
		&auth_request, TEST_REQUESTS_TOKEN, TEST_REQUESTS_SOURCE,
		TEST_REQUESTS_ACTION, TEST_REQUESTS_ROLE
	);

	json_t *body = test_requests_body (&auth_request);
	test_requests_check_integer (body, "type", PERCEPTHOR_AUTH_TYPE_ROLE);
	test_requests_check_string (body, "source", TEST_REQUESTS_SOURCE);
	test_requests_check_string (body, "action", TEST_REQUESTS_ACTION);
	test_requests_check_string (body, "role", TEST_REQUESTS_ROLE);
	json_decref (body);

}

// the action of a role is optional: a missing or empty one is left out, the source never
static void test_requests_role_without_action (void) {

	static const char *actions[] = { NULL, "" };

	for (size_t i = 0; i < 2; i++) {
		AuthRequest auth_request = { 0 };
		auth_request_create_role (
			&auth_request, TEST_REQUESTS_TOKEN, TEST_REQUESTS_SOURCE,
			actions[i], TEST_REQUESTS_ROLE
		);

		json_t *body = test_requests_body (&auth_request);
		test_requests_check_string (body, "source", TEST_REQUESTS_SOURCE);
		test_requests_check_string (body, "role", TEST_REQUESTS_ROLE);
		test_check_null_ptr (json_object_get (body, "action"));
		json_decref (body);
	}

}

static void test_requests_service (void) {

	AuthRequest auth_request = { 0 };
	auth_request_create_service (&auth_request, TEST_REQUESTS_TOKEN, TEST_REQUESTS_SOURCE, TEST_REQUESTS_SERVICE);

	json_t *body = test_requests_body (&auth_request);
	test_requests_check_integer (body, "type", PERCEPTHOR_AUTH_TYPE_SERVICE);
	test_requests_check_string (body, "service", TEST_REQUESTS_SERVICE);
	json_decref (body);

}

static void test_requests_single_permissions (void) {

	AuthRequest auth_request = { 0 };
	auth_request_create_single_permissions (
		&auth_request, TEST_REQUESTS_TOKEN, TEST_REQUESTS_SOURCE,
		PERMISSIONS_TYPE_ORGANIZATION, TEST_REQUESTS_RESOURCE, TEST_REQUESTS_ACTION
	);

	json_t *body = test_requests_body (&auth_request);
	test_requests_check_integer (body, "type", PERCEPTHOR_AUTH_TYPE_PERMISSIONS);
	test_requests_check_integer (body, "scope", PERCEPTHOR_AUTH_SCOPE_SINGLE);
	test_requests_check_integer (body, "permissions_type", PERMISSIONS_TYPE_ORGANIZATION);
	test_requests_check_string (body, "resource", TEST_REQUESTS_RESOURCE);
	test_requests_check_string (body, "action", TEST_REQUESTS_ACTION);
	json_decref (body);

}

static void test_requests_management_permissions (void) {

	AuthRequest auth_request = { 0 };
	auth_request_create_management_permissions (
		&auth_request, TEST_REQUESTS_TOKEN, TEST_REQUESTS_SOURCE,
		PERMISSIONS_TYPE_PROJECT, TEST_REQUESTS_ACTION
	);

	json_t *body = test_requests_body (&auth_request);
	test_requests_check_integer (body, "scope", PERCEPTHOR_AUTH_SCOPE_MANAGEMENT);
	test_requests_check_integer (body, "permissions_type", PERMISSIONS_TYPE_PROJECT);
	test_requests_check_string (body, "action", TEST_REQUESTS_ACTION);
	json_decref (body);

	auth_request_create_management_permissions (
		&auth_request, TEST_REQUESTS_TOKEN, TEST_REQUESTS_SOURCE,
		PERMISSIONS_TYPE_PROJECT, NULL
	);

	body = test_requests_body (&auth_request);
	test_check_null_ptr (json_object_get (body, "action"));
	json_decref (body);

}

// a quote in a value is escaped: it can not add a field nor overwrite the scope
static void test_requests_injection (void) {

	AuthRequest auth_request = { 0 };
	auth_request_create_single_permissions (
		&auth_request, TEST_REQUESTS_TOKEN, TEST_REQUESTS_SOURCE,
		PERMISSIONS_TYPE_ORGANIZATION, injected_resource, TEST_REQUESTS_ACTION
	);

	json_t *body = test_requests_body (&auth_request);
	test_requests_check_integer (body, "scope", PERCEPTHOR_AUTH_SCOPE_SINGLE);
	test_requests_check_string (body, "resource", injected_resource);
	test_check_null_ptr (json_object_get (body, "x"));
	test_check_unsigned_eq (json_object_size (body), 6, NULL);
	json_decref (body);

	auth_request_create_action (
		&auth_request, TEST_REQUESTS_TOKEN, "tickets\\\"", "a\"b\nc"
	);

	body = test_requests_body (&auth_request);
	test_requests_check_string (body, "source", "tickets\\\"");
	test_requests_check_string (body, "action", "a\"b\nc");
	json_decref (body);

}

// a body that does not fit is never sent, instead of being sent truncated
static void test_requests_body_too_large (void) {

	char long_resource[TEST_REQUESTS_BODY_SIZE];
	(void) memset (long_resource, 'a', TEST_REQUESTS_BODY_SIZE - 1);
	long_resource[TEST_REQUESTS_BODY_SIZE - 1] = '\0';

	AuthRequest auth_request = { 0 };
	auth_request_create_single_permissions (
		&auth_request, TEST_REQUESTS_TOKEN, TEST_REQUESTS_SOURCE,
		PERMISSIONS_TYPE_ORGANIZATION, long_resource, TEST_REQUESTS_ACTION
	);

	test_check_false (auth_request_is_valid (&auth_request));
	test_check_unsigned_eq (auth_request.body_len, 0, NULL);
	test_check_str_empty (auth_request.body);

	test_check_unsigned_eq (
		auth_request_authentication ("http://127.0.0.1:1/api/auth/check", &auth_request),
		REQUEST_RESULT_FAILED, NULL
	);

}

// a value that fits the body exactly at its limit is still sent
static void test_requests_body_limit (void) {

	AuthRequest auth_request = { 0 };
	auth_request_create (&auth_request, TEST_REQUESTS_TOKEN, "");

	// {"type":1} plus ,"source":"" and the value
	const size_t base = strlen ("{\"type\":1,\"source\":\"\"}");
	const size_t fits = (AUTH_REQUEST_SIZE - 1) - base;

	char source[AUTH_REQUEST_SIZE];
	(void) memset (source, 's', fits);
	source[fits] = '\0';

	auth_request_create (&auth_request, TEST_REQUESTS_TOKEN, source);
	test_check_true (auth_request_is_valid (&auth_request));
	test_check_unsigned_eq (auth_request.body_len, AUTH_REQUEST_SIZE - 1, NULL);

	source[fits] = 's';
	source[fits + 1] = '\0';

	auth_request_create (&auth_request, TEST_REQUESTS_TOKEN, source);
	test_check_false (auth_request_is_valid (&auth_request));

}

static void test_requests_header_too_large (void) {

	char long_token[TEST_REQUESTS_LONG_SIZE];
	(void) memset (long_token, 't', TEST_REQUESTS_LONG_SIZE - 1);
	long_token[TEST_REQUESTS_LONG_SIZE - 1] = '\0';

	AuthRequest auth_request = { 0 };
	auth_request_create (&auth_request, long_token, TEST_REQUESTS_SOURCE);

	test_check_false (auth_request_is_valid (&auth_request));
	test_check_unsigned_eq (auth_request.auth_header_len, 0, NULL);

	auth_request_create (&auth_request, NULL, TEST_REQUESTS_SOURCE);
	test_check_false (auth_request_is_valid (&auth_request));

}

// a value that is not valid utf-8 can not be serialized, so the request is not sent
static void test_requests_invalid_utf8 (void) {

	AuthRequest auth_request = { 0 };
	auth_request_create_action (&auth_request, TEST_REQUESTS_TOKEN, TEST_REQUESTS_SOURCE, "\xff\xfe");

	test_check_false (auth_request_is_valid (&auth_request));

}

// the client and the id of the request are optional headers, never sent truncated
static void test_requests_client (void) {

	AuthRequest auth_request = { 0 };

	auth_request_set_client (&auth_request, "203.0.113.5", "request-1");
	test_check_str_eq (auth_request.forwarded_header, "X-Forwarded-For: 203.0.113.5", NULL);
	test_check_str_eq (auth_request.request_id_header, "X-Request-Id: request-1", NULL);

	auth_request_set_client (&auth_request, "2001:db8:ffff:ffff:ffff:ffff:255.255.255.255", "");
	test_check_str_eq (auth_request.forwarded_header, "X-Forwarded-For: 2001:db8:ffff:ffff:ffff:ffff:255.255.255.255", NULL);
	test_check_str_eq (auth_request.request_id_header, "", NULL);

	auth_request_set_client (&auth_request, NULL, NULL);
	test_check_str_eq (auth_request.forwarded_header, "", NULL);
	test_check_str_eq (auth_request.request_id_header, "", NULL);

	char long_id[TEST_REQUESTS_LONG_SIZE] = { 0 };
	(void) memset (long_id, 'a', TEST_REQUESTS_LONG_SIZE - 1);
	auth_request_set_client (&auth_request, long_id, long_id);
	test_check_str_eq (auth_request.forwarded_header, "", NULL);
	test_check_str_eq (auth_request.request_id_header, "", NULL);

	auth_request_set_client (NULL, "203.0.113.5", "request-1");

}

// cerver gives the zone of a link local client, up to NETWORK_ADDRESS_STRING_SIZE bytes
static void test_requests_client_zoned (void) {

	AuthRequest auth_request = { 0 };

	auth_request_set_client (&auth_request, TEST_REQUESTS_ZONED_ADDRESS, "request-1");
	test_check_str_eq (auth_request.forwarded_header, "X-Forwarded-For: " TEST_REQUESTS_ZONED_ADDRESS, NULL);

	auth_request_set_client (&auth_request, "fe80::1%eth0", NULL);
	test_check_str_eq (auth_request.forwarded_header, "X-Forwarded-For: fe80::1%eth0", NULL);

}

// the largest values of a single permissions route fit the body, even when every byte is escaped
static void test_requests_single_permissions_limit (void) {

	char resource[AUTH_RESOURCE_SIZE];
	(void) memset (resource, TEST_REQUESTS_ESCAPED, AUTH_RESOURCE_SIZE - 1);
	resource[AUTH_RESOURCE_SIZE - 1] = '\0';

	char action[AUTH_ACTION_SIZE];
	(void) memset (action, TEST_REQUESTS_ESCAPED, AUTH_ACTION_SIZE - 1);
	action[AUTH_ACTION_SIZE - 1] = '\0';

	AuthRequest auth_request = { 0 };
	auth_request_create_single_permissions (
		&auth_request, TEST_REQUESTS_TOKEN, TEST_REQUESTS_SOURCE,
		PERMISSIONS_TYPE_ORGANIZATION, resource, action
	);

	json_t *body = test_requests_body (&auth_request);
	test_requests_check_string (body, "resource", resource);
	test_requests_check_string (body, "action", action);
	json_decref (body);

}

// the builders and the end of a request accept NULL, and an end without an answer does nothing
static void test_requests_null (void) {

	auth_request_create (NULL, TEST_REQUESTS_TOKEN, TEST_REQUESTS_SOURCE);
	auth_request_create_action (NULL, TEST_REQUESTS_TOKEN, TEST_REQUESTS_SOURCE, TEST_REQUESTS_ACTION);
	auth_request_create_single_permissions (
		NULL, TEST_REQUESTS_TOKEN, TEST_REQUESTS_SOURCE,
		PERMISSIONS_TYPE_ORGANIZATION, TEST_REQUESTS_RESOURCE, TEST_REQUESTS_ACTION
	);

	auth_request_end (NULL);

	AuthRequest auth_request = { 0 };
	auth_request_end (&auth_request);
	test_check_null_ptr (auth_request.response);
	test_check_unsigned_eq (auth_request.response_len, 0, NULL);

}

static void test_requests_without_address (void) {

	AuthRequest auth_request = { 0 };
	auth_request_create (&auth_request, TEST_REQUESTS_TOKEN, TEST_REQUESTS_SOURCE);

	test_check_unsigned_eq (auth_request_authentication (NULL, &auth_request), REQUEST_RESULT_FAILED, NULL);
	test_check_unsigned_eq (auth_request_authentication ("", &auth_request), REQUEST_RESULT_FAILED, NULL);
	test_check_unsigned_eq (auth_request_authentication ("http://127.0.0.1:1/x", NULL), REQUEST_RESULT_FAILED, NULL);

}

int main (int argc, char **argv) {

	(void) printf ("Testing REQUESTS...\n");

	test_requests_result ();
	test_requests_new ();
	test_requests_token ();
	test_requests_action ();
	test_requests_role ();
	test_requests_role_without_action ();
	test_requests_service ();
	test_requests_single_permissions ();
	test_requests_management_permissions ();
	test_requests_injection ();
	test_requests_body_too_large ();
	test_requests_body_limit ();
	test_requests_header_too_large ();
	test_requests_invalid_utf8 ();
	test_requests_client ();
	test_requests_client_zoned ();
	test_requests_single_permissions_limit ();
	test_requests_null ();
	test_requests_without_address ();

	(void) printf ("Done!\n");

	return 0;

}
