#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <auth/auth.h>

#include "fuzz.h"

// any answer of the auth service is read into every kind of auth values
// without crashing, leaking or reading out of bounds
int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size) {

	char *response = fuzz_string (data, size);
	if (response) {
		for (unsigned int type = PERCEPTHOR_AUTH_TYPE_NONE; type <= PERCEPTHOR_AUTH_TYPE_COMPLETE; type++) {
			PercepthorAuth *auth = percepthor_auth_create ((PercepthorAuthType) type);
			if (auth) {
				(void) percepthor_auth_handle_response (auth, response);

				if (percepthor_auth_permissions_iter_start (auth)) {
					while (percepthor_auth_permissions_iter_get_next (auth));
				}

				percepthor_auth_delete (auth);
			}
		}

		free (response);
	}

	return 0;

}
