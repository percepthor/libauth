#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <cerver/http/json/json.h>

#include <auth/auth.h>
#include <auth/permissions.h>
#include <auth/requests.h>

#include "fuzz.h"

// the values of a request split from the input; every body that is sent is a json
// object whose resource is exactly the one that was given, so no value can add a field
#define FUZZ_REQUEST_FIELDS			4

static void fuzz_request_check (const AuthRequest *auth_request, const char *resource) {

	if (auth_request_is_valid (auth_request)) {
		json_error_t error;
		json_t *body = json_loads (auth_request->body, 0, &error);
		if (!json_is_object (body)) abort ();

		if (resource && resource[0]) {
			const json_t *value = json_object_get (body, "resource");
			if (!json_is_string (value) || strcmp (json_string_value (value), resource)) abort ();

			const json_t *scope = json_object_get (body, "scope");
			if (!json_is_integer (scope) || (json_integer_value (scope) != PERCEPTHOR_AUTH_SCOPE_SINGLE)) abort ();
		}

		json_decref (body);
	}

}

int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size) {

	char *input = fuzz_string (data, size);
	if (input) {
		// token, source, action and resource, separated by new lines
		char *fields[FUZZ_REQUEST_FIELDS] = { NULL, NULL, NULL, NULL };
		char *next = input;
		for (unsigned int i = 0; i < FUZZ_REQUEST_FIELDS; i++) {
			fields[i] = next;
			char *end = next ? strchr (next, '\n') : NULL;
			if (end) {
				*end = '\0';
				next = end + 1;
			}

			else {
				next = NULL;
			}
		}

		AuthRequest auth_request;
		(void) memset (&auth_request, 0, sizeof (AuthRequest));

		auth_request_create_single_permissions (
			&auth_request, fields[0], fields[1], PERMISSIONS_TYPE_ORGANIZATION, fields[3], fields[2]
		);

		fuzz_request_check (&auth_request, fields[3]);

		auth_request_create (&auth_request, fields[0], fields[1]);
		fuzz_request_check (&auth_request, NULL);

		auth_request_create_action (&auth_request, fields[0], fields[1], fields[2]);
		fuzz_request_check (&auth_request, NULL);

		auth_request_create_role (&auth_request, fields[0], fields[1], fields[2], fields[3]);
		fuzz_request_check (&auth_request, NULL);

		auth_request_create_service (&auth_request, fields[0], fields[1], fields[2]);
		fuzz_request_check (&auth_request, NULL);

		auth_request_create_management_permissions (
			&auth_request, fields[0], fields[1], PERMISSIONS_TYPE_PROJECT, fields[2]
		);

		fuzz_request_check (&auth_request, NULL);

		free (input);
	}

	return 0;

}
