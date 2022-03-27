#include <stdlib.h>
#include <stdio.h>
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
	const char *service_name,
	const char *auth_service_address
) {

	AuthService *auth_service = auth_service_new ();
	if (auth_service) {
		if (service_id) {
			auth_service->service_id_len = snprintf (
				auth_service->service_id,
				AUTH_SERVICE_ID_SIZE,
				"%s", service_id
			);
		}

		if (service_name) {
			auth_service->service_name_len = snprintf (
				auth_service->service_name,
				AUTH_SERVICE_NAME_SIZE,
				"%s", service_name
			);
		}

		if (auth_service_address) {
			auth_service->auth_service_address_len = snprintf (
				auth_service->auth_service_address,
				AUTH_SERVICE_ADDRESS_SIZE,
				"%s", auth_service_address
			);
		}
	}

	return auth_service;

}

void auth_service_print (const AuthService *auth_service) {

	(void) printf ("Auth Service:\n");

	if (auth_service->service_id_len) {
		(void) printf (
			"\tid [%d]: %s\n",
			auth_service->service_id_len, auth_service->service_id
		);
	}

	if (auth_service->service_name_len) {
		(void) printf (
			"\tName [%d]: %s\n",
			auth_service->service_name_len, auth_service->service_name
		);
	}

	if (auth_service->auth_service_address_len) {
		(void) printf (
			"\tDescription [%d]: %s\n\n",
			auth_service->auth_service_address_len, auth_service->auth_service_address
		);
	}

}
