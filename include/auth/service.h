#ifndef _PERCEPTHOR_AUTH_SERVICE_H_
#define _PERCEPTHOR_AUTH_SERVICE_H_

#include "auth/config.h"

/**
 * @file service.h
 * @brief The service that authenticates its requests: its id, its name and the
 * address of the auth service.
 *
 * The AuthService is the custom data of the HTTP cerver of the service
 * (http_cerver_set_custom_data ()), the authentication handlers read it from there.
 */

#define AUTH_SERVICE_ID_SIZE				32
#define AUTH_SERVICE_NAME_SIZE				128
#define AUTH_SERVICE_ADDRESS_SIZE			128

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief The service that sends the requests to the auth service.
 *
 * The id is only needed by the service routes (PERCEPTHOR_AUTH_TYPE_SERVICE),
 * the name is the source of every request.
 */
typedef struct AuthService {

	int service_id_len;
	char service_id[AUTH_SERVICE_ID_SIZE];

	int service_name_len;
	char service_name[AUTH_SERVICE_NAME_SIZE];

	int auth_service_address_len;
	char auth_service_address[AUTH_SERVICE_ADDRESS_SIZE];

} AuthService;

/**
 * @brief Allocates an empty AuthService.
 * @return The AuthService, released with auth_service_delete (), NULL on error.
 */
AUTH_EXPORT AuthService *auth_service_new (void);

/**
 * @brief Releases an AuthService.
 * @param auth_service_ptr The AuthService, NULL does nothing.
 */
AUTH_EXPORT void auth_service_delete (void *auth_service_ptr);

/**
 * @brief Creates the AuthService of a service.
 *
 * A value longer than its buffer is truncated.
 * @param service_id The id of the service, can be NULL for a service without service routes.
 * @param service_name The name of the service, the source of its requests.
 * @param auth_service_address The url of the auth service, like "http://auth:5000/api/auth/check".
 * @return The AuthService, released with auth_service_delete (), NULL on error.
 */
AUTH_EXPORT AuthService *auth_service_create (
	const char *service_id,
	const char *service_name,
	const char *auth_service_address
);

/**
 * @brief Prints the values of an AuthService.
 * @param auth_service The AuthService, NULL does nothing.
 */
AUTH_EXPORT void auth_service_print (const AuthService *auth_service);

#ifdef __cplusplus
}
#endif

#endif
