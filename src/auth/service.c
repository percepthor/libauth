#include <stdlib.h>
#include <string.h>

#include "auth/service.h"

AuthService *auth_service_new (void) {

	AuthService *auth_service = (AuthService *) malloc (sizeof (AuthService));
	if (auth_service) {
		(void) memset (auth_service, 0, sizeof (AuthService));
	}

	return auth_service;

}

void auth_service_delete (void *auth_service_ptr) {

	if (auth_service_ptr) free (auth_service_ptr);

}

AuthService *auth_service_create (
	const char *service_id,
	const char *auth_service_address
) {

	AuthService *auth_service = auth_service_new ();
	if (auth_service) {
		(void) strncpy (
			auth_service->service_id,
			service_id,
			AUTH_SERVICE_ID_SIZE - 1
		);

		auth_service->service_id_len = (unsigned int) strlen (
			auth_service->service_id
		);

		(void) strncpy (
			auth_service->auth_service_address,
			auth_service_address,
			AUTH_SERVICE_ADDRESS_SIZE - 1
		);

		auth_service->auth_service_address_len = (unsigned int) strlen (
			auth_service->auth_service_address
		);
	}

	return auth_service;

}
