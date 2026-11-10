#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <auth/auth.h>
#include <auth/permissions.h>
#include <auth/token.h>

#include "test.h"

// the auth values and the response of the auth service read into them

// bugs this suite fixed:
// - an integer mask was read with atoll (json_string_value ()), atoll (NULL)
// - a value of the token that was not a string was printed with "%s" from NULL
// - a resource action that was not a string created an action from NULL
// - the getters dereferenced the NULL custom data of a request without auth
// - a t_type outside of PercepthorTokenType was cast into the enum
// - the response of a NULL auth was dereferenced

#define TEST_AUTH_ID				"507f1f77bcf86cd799439011"
#define TEST_AUTH_ORGANIZATION		"507f1f77bcf86cd799439012"
#define TEST_AUTH_ROLE				"507f1f77bcf86cd799439013"
#define TEST_AUTH_USER				"507f1f77bcf86cd799439014"
#define TEST_AUTH_RESOURCE			"507f1f77bcf86cd799439015"

#define TEST_AUTH_MASK				4294967296

static const char *token_response = {
	"{\"token\": {"
	"\"id\": \"" TEST_AUTH_ID "\", \"t_type\": 4, "
	"\"organization\": \"" TEST_AUTH_ORGANIZATION "\", \"role\": \"" TEST_AUTH_ROLE "\", "
	"\"user\": \"" TEST_AUTH_USER "\", \"username\": \"erick\""
	"}}"
};

static void test_auth_types (void) {

	test_check_str_eq (percepthor_auth_type_to_string (PERCEPTHOR_AUTH_TYPE_NONE), "None", NULL);
	test_check_str_eq (percepthor_auth_type_to_string (PERCEPTHOR_AUTH_TYPE_TOKEN), "Token", NULL);
	test_check_str_eq (percepthor_auth_type_to_string (PERCEPTHOR_AUTH_TYPE_ACTION), "Action", NULL);
	test_check_str_eq (percepthor_auth_type_to_string (PERCEPTHOR_AUTH_TYPE_ROLE), "Role", NULL);
	test_check_str_eq (percepthor_auth_type_to_string (PERCEPTHOR_AUTH_TYPE_SERVICE), "Service", NULL);
	test_check_str_eq (percepthor_auth_type_to_string (PERCEPTHOR_AUTH_TYPE_PERMISSIONS), "Permissions", NULL);
	test_check_str_eq (percepthor_auth_type_to_string (PERCEPTHOR_AUTH_TYPE_MULTIPLE), "Multiple", NULL);
	test_check_str_eq (percepthor_auth_type_to_string (PERCEPTHOR_AUTH_TYPE_COMPLETE), "Complete", NULL);
	test_check_str_eq (percepthor_auth_type_to_string ((PercepthorAuthType) 64), "None", NULL);

	test_check_str_eq (percepthor_auth_scope_to_string (PERCEPTHOR_AUTH_SCOPE_NONE), "None", NULL);
	test_check_str_eq (percepthor_auth_scope_to_string (PERCEPTHOR_AUTH_SCOPE_SINGLE), "Single", NULL);
	test_check_str_eq (percepthor_auth_scope_to_string (PERCEPTHOR_AUTH_SCOPE_MANAGEMENT), "Management", NULL);
	test_check_str_eq (percepthor_auth_scope_to_string ((PercepthorAuthScope) 64), "None", NULL);

}

static void test_auth_create (void) {

	for (unsigned int type = PERCEPTHOR_AUTH_TYPE_NONE; type <= PERCEPTHOR_AUTH_TYPE_COMPLETE; type++) {
		PercepthorAuth *auth = percepthor_auth_create ((PercepthorAuthType) type);
		test_check_ptr (auth);

		test_check_unsigned_eq (percepthor_auth_get_type (auth), type, NULL);
		test_check_unsigned_eq (percepthor_auth_get_scope (auth), PERCEPTHOR_AUTH_SCOPE_NONE, NULL);
		test_check_str_empty (percepthor_auth_get_token_id (auth));
		test_check_false (percepthor_auth_get_admin (auth));
		test_check_long_int_eq (percepthor_auth_get_mask (auth), 0, NULL);

		// only the permissions keep a list of resources
		if (type == PERCEPTHOR_AUTH_TYPE_PERMISSIONS) {
			test_check_ptr (percepthor_auth_get_permissions (auth));
		}

		else {
			test_check_null_ptr (percepthor_auth_get_permissions (auth));
			test_check_false (percepthor_auth_permissions_iter_start (auth));
		}

		percepthor_auth_delete (auth);
	}

	percepthor_auth_delete (NULL);

}

// a request that was not authenticated by libauth has NULL custom data
static void test_auth_getters_without_auth (void) {

	test_check_unsigned_eq (percepthor_auth_get_type (NULL), PERCEPTHOR_AUTH_TYPE_NONE, NULL);
	test_check_unsigned_eq (percepthor_auth_get_scope (NULL), PERCEPTHOR_AUTH_SCOPE_NONE, NULL);
	test_check_null_ptr (percepthor_auth_get_resource (NULL));
	test_check_null_ptr (percepthor_auth_get_action (NULL));
	test_check_false (percepthor_auth_get_admin (NULL));
	test_check_null_ptr (percepthor_auth_get_permissions (NULL));
	test_check_false (percepthor_auth_permissions_iter_start (NULL));
	test_check_null_ptr (percepthor_auth_permissions_iter_get_next (NULL));
	test_check_null_ptr (percepthor_auth_get_token_id (NULL));
	test_check_unsigned_eq (percepthor_auth_get_token_type (NULL), PERCEPTHOR_TOKEN_TYPE_NONE, NULL);
	test_check_null_ptr (percepthor_auth_get_token_organization (NULL));
	test_check_null_ptr (percepthor_auth_get_token_permissions (NULL));
	test_check_null_ptr (percepthor_auth_get_token_role (NULL));
	test_check_null_ptr (percepthor_auth_get_token_user (NULL));
	test_check_null_ptr (percepthor_auth_get_token_username (NULL));
	test_check_long_int_eq (percepthor_auth_get_mask (NULL), 0, NULL);

	percepthor_auth_print_token (NULL);

}

static void test_auth_response_token (void) {

	PercepthorAuth *auth = percepthor_auth_create (PERCEPTHOR_AUTH_TYPE_TOKEN);

	test_check_unsigned_eq (percepthor_auth_handle_response (auth, token_response), 0, NULL);

	test_check_str_eq (percepthor_auth_get_token_id (auth), TEST_AUTH_ID, NULL);
	test_check_unsigned_eq (percepthor_auth_get_token_type (auth), PERCEPTHOR_TOKEN_TYPE_USER, NULL);
	test_check_str_eq (percepthor_auth_get_token_organization (auth), TEST_AUTH_ORGANIZATION, NULL);
	test_check_str_eq (percepthor_auth_get_token_role (auth), TEST_AUTH_ROLE, NULL);
	test_check_str_eq (percepthor_auth_get_token_user (auth), TEST_AUTH_USER, NULL);
	test_check_str_eq (percepthor_auth_get_token_username (auth), "erick", NULL);

	percepthor_auth_print_token (auth);

	percepthor_auth_delete (auth);

}

// a value of another json type leaves the field empty
static void test_auth_response_token_types (void) {

	PercepthorAuth *auth = percepthor_auth_create (PERCEPTHOR_AUTH_TYPE_TOKEN);

	test_check_unsigned_eq (percepthor_auth_handle_response (
		auth,
		"{\"token\": {\"id\": 5, \"t_type\": \"4\", \"organization\": null, "
		"\"role\": [], \"user\": {}, \"username\": true}}"
	), 0, NULL);

	test_check_str_empty (percepthor_auth_get_token_id (auth));
	test_check_unsigned_eq (percepthor_auth_get_token_type (auth), PERCEPTHOR_TOKEN_TYPE_NONE, NULL);
	test_check_str_empty (percepthor_auth_get_token_organization (auth));
	test_check_str_empty (percepthor_auth_get_token_role (auth));
	test_check_str_empty (percepthor_auth_get_token_user (auth));
	test_check_str_empty (percepthor_auth_get_token_username (auth));

	percepthor_auth_delete (auth);

}

// a value longer than its field is truncated, never overflowed
static void test_auth_response_token_truncated (void) {

	PercepthorAuth *auth = percepthor_auth_create (PERCEPTHOR_AUTH_TYPE_TOKEN);

	char response[1024];
	(void) snprintf (
		response, sizeof (response),
		"{\"token\": {\"id\": \"%0128d\"}}", 1
	);

	test_check_unsigned_eq (percepthor_auth_handle_response (auth, response), 0, NULL);
	test_check_str_len (percepthor_auth_get_token_id (auth), AUTH_ID_SIZE - 1, NULL);

	percepthor_auth_delete (auth);

}

// the auth service answers the mask as a number, or as the string it read from redis
static void test_auth_response_mask (void) {

	PercepthorAuth *auth = percepthor_auth_create (PERCEPTHOR_AUTH_TYPE_SERVICE);
	test_check_unsigned_eq (percepthor_auth_handle_response (auth, "{\"mask\": 4294967296}"), 0, NULL);
	test_check_long_int_eq (percepthor_auth_get_mask (auth), TEST_AUTH_MASK, NULL);
	percepthor_auth_delete (auth);

	auth = percepthor_auth_create (PERCEPTHOR_AUTH_TYPE_SERVICE);
	test_check_unsigned_eq (percepthor_auth_handle_response (auth, "{\"mask\": \"4294967296\"}"), 0, NULL);
	test_check_long_int_eq (percepthor_auth_get_mask (auth), TEST_AUTH_MASK, NULL);
	percepthor_auth_delete (auth);

	auth = percepthor_auth_create (PERCEPTHOR_AUTH_TYPE_SERVICE);
	test_check_unsigned_eq (percepthor_auth_handle_response (auth, "{\"mask\": null}"), 0, NULL);
	test_check_long_int_eq (percepthor_auth_get_mask (auth), 0, NULL);
	percepthor_auth_delete (auth);

}

static void test_auth_response_resources (void) {

	PercepthorAuth *auth = percepthor_auth_create (PERCEPTHOR_AUTH_TYPE_PERMISSIONS);

	test_check_unsigned_eq (percepthor_auth_handle_response (
		auth,
		"{\"token\": {\"id\": \"" TEST_AUTH_ID "\"}, \"admin\": false, \"resources\": ["
		"{\"_id\": \"" TEST_AUTH_RESOURCE "\", \"actions\": [\"read\", 5, null, \"write\"]}, "
		"7, "
		"{\"_id\": 9, \"actions\": \"read\"}"
		"]}"
	), 0, NULL);

	test_check_false (percepthor_auth_get_admin (auth));
	test_check_unsigned_eq (percepthor_auth_get_permissions (auth)->size, 2, NULL);

	test_check_true (percepthor_auth_permissions_iter_start (auth));

	const Permissions *first = percepthor_auth_permissions_iter_get_next (auth);
	test_check_ptr (first);
	test_check_str_eq (permissions_get_resource (first), TEST_AUTH_RESOURCE, NULL);
	test_check_unsigned_eq (first->actions->size, 2, NULL);
	test_check_true (permissions_has_action (first, "read"));
	test_check_true (permissions_has_action (first, "write"));
	test_check_false (permissions_has_action (first, "delete"));

	const Permissions *second = percepthor_auth_permissions_iter_get_next (auth);
	test_check_ptr (second);
	test_check_str_empty (permissions_get_resource (second));
	test_check_unsigned_eq (second->actions->size, 0, NULL);

	test_check_null_ptr (percepthor_auth_permissions_iter_get_next (auth));

	percepthor_auth_delete (auth);

}

// only the permissions keep the resources, any other auth ignores them
static void test_auth_response_resources_ignored (void) {

	PercepthorAuth *auth = percepthor_auth_create (PERCEPTHOR_AUTH_TYPE_TOKEN);

	test_check_unsigned_eq (percepthor_auth_handle_response (
		auth, "{\"resources\": [{\"_id\": \"" TEST_AUTH_RESOURCE "\"}]}"
	), 0, NULL);

	test_check_null_ptr (percepthor_auth_get_permissions (auth));

	percepthor_auth_delete (auth);

}

static void test_auth_response_admin (void) {

	PercepthorAuth *auth = percepthor_auth_create (PERCEPTHOR_AUTH_TYPE_PERMISSIONS);
	test_check_unsigned_eq (percepthor_auth_handle_response (auth, "{\"admin\": true}"), 0, NULL);
	test_check_true (percepthor_auth_get_admin (auth));
	percepthor_auth_delete (auth);

	auth = percepthor_auth_create (PERCEPTHOR_AUTH_TYPE_PERMISSIONS);
	test_check_unsigned_eq (percepthor_auth_handle_response (auth, "{\"admin\": \"true\"}"), 0, NULL);
	test_check_false (percepthor_auth_get_admin (auth));
	percepthor_auth_delete (auth);

}

// a body that is not a json object is never accepted
static void test_auth_response_invalid (void) {

	static const char *invalid_responses[] = {
		"", "{", "not json", "[1, 2]", "\"token\"", "5", "null"
	};

	for (size_t i = 0; i < (sizeof (invalid_responses) / sizeof (invalid_responses[0])); i++) {
		PercepthorAuth *auth = percepthor_auth_create (PERCEPTHOR_AUTH_TYPE_TOKEN);
		test_check_unsigned_eq (percepthor_auth_handle_response (auth, invalid_responses[i]), 1, invalid_responses[i]);
		percepthor_auth_delete (auth);
	}

	PercepthorAuth *auth = percepthor_auth_create (PERCEPTHOR_AUTH_TYPE_TOKEN);
	test_check_unsigned_eq (percepthor_auth_handle_response (auth, "{\"oki\": \"doki\"}"), 0, NULL);
	test_check_str_empty (percepthor_auth_get_token_id (auth));
	percepthor_auth_delete (auth);

	// without the auth values or the answer there is nothing to read
	test_check_unsigned_eq (percepthor_auth_handle_response (NULL, token_response), 1, NULL);

	auth = percepthor_auth_create (PERCEPTHOR_AUTH_TYPE_TOKEN);
	test_check_unsigned_eq (percepthor_auth_handle_response (auth, NULL), 1, NULL);
	percepthor_auth_delete (auth);

}

// a token type that PercepthorTokenType does not have is read as none, never cast into the enum
static void test_auth_response_token_type_unknown (void) {

	static const char *unknown_types[] = {
		"{\"token\": {\"t_type\": 99}}", "{\"token\": {\"t_type\": -1}}", "{\"token\": {\"t_type\": 4294967300}}"
	};

	for (size_t i = 0; i < (sizeof (unknown_types) / sizeof (unknown_types[0])); i++) {
		PercepthorAuth *auth = percepthor_auth_create (PERCEPTHOR_AUTH_TYPE_TOKEN);
		test_check_unsigned_eq (percepthor_auth_handle_response (auth, unknown_types[i]), 0, unknown_types[i]);
		test_check_unsigned_eq (percepthor_auth_get_token_type (auth), PERCEPTHOR_TOKEN_TYPE_NONE, unknown_types[i]);
		percepthor_auth_delete (auth);
	}

	PercepthorAuth *auth = percepthor_auth_create (PERCEPTHOR_AUTH_TYPE_TOKEN);
	test_check_unsigned_eq (percepthor_auth_handle_response (auth, "{\"token\": {\"t_type\": 2}}"), 0, NULL);
	test_check_unsigned_eq (percepthor_auth_get_token_type (auth), PERCEPTHOR_TOKEN_TYPE_TEMPORARY, NULL);
	percepthor_auth_delete (auth);

}

int main (int argc, char **argv) {

	(void) printf ("Testing AUTH...\n");

	test_auth_types ();
	test_auth_create ();
	test_auth_getters_without_auth ();
	test_auth_response_token ();
	test_auth_response_token_types ();
	test_auth_response_token_truncated ();
	test_auth_response_mask ();
	test_auth_response_resources ();
	test_auth_response_resources_ignored ();
	test_auth_response_admin ();
	test_auth_response_invalid ();
	test_auth_response_token_type_unknown ();

	(void) printf ("Done!\n");

	return 0;

}
