#ifndef _PERCEPTHOR_AUTH_SERVICE_H_
#define _PERCEPTHOR_AUTH_SERVICE_H_

#include "auth/config.h"

#define AUTH_SERVICE_ID_SIZE				32
#define AUTH_SERVICE_NAME_SIZE				128
#define AUTH_SERVICE_ADDRESS_SIZE			128

#ifdef __cplusplus
extern "C" {
#endif

typedef struct AuthService {

	int service_id_len;
	char service_id[AUTH_SERVICE_ID_SIZE];

	int service_name_len;
	char service_name[AUTH_SERVICE_NAME_SIZE];

	int auth_service_address_len;
	char auth_service_address[AUTH_SERVICE_ADDRESS_SIZE];

} AuthService;

AUTH_PRIVATE AuthService *auth_service_new (void);

AUTH_PRIVATE void auth_service_delete (void *auth_service_ptr);

AUTH_EXPORT AuthService *auth_service_create (
	const char *service_id,
	const char *service_name,
	const char *auth_service_address
);

AUTH_EXPORT void auth_service_print (const AuthService *auth_service);

#ifdef __cplusplus
}
#endif

#endif