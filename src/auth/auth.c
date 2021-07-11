#include <stdlib.h>
#include <string.h>

#include "auth/auth.h"

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
