#ifndef _PERCEPTHOR_AUTH_REQUESTS_H_
#define _PERCEPTHOR_AUTH_REQUESTS_H_

#include <stddef.h>
#include <stdbool.h>

#include "auth/auth.h"
#include "auth/config.h"
#include "auth/permissions.h"

#define AUTH_HEADER_SIZE		1024
#define AUTH_REQUEST_SIZE		512
#define AUTH_RESPONSE_SIZE		1024

// limits for a request to the auth service,
// so a slow or hung auth service can not block the caller's thread forever;
// the test build lowers them to keep the slow auth service cases short
#ifndef AUTH_REQUEST_CONNECT_TIMEOUT
#define AUTH_REQUEST_CONNECT_TIMEOUT	10
#endif

#ifndef AUTH_REQUEST_TIMEOUT
#define AUTH_REQUEST_TIMEOUT			30
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define REQUEST_RESULT_MAP(XX)			\
	XX(0,  NONE,      	None)			\
	XX(1,  FAILED,      Failed)			\
	XX(2,  BAD_STATUS,  Bad Status)

typedef enum RequestResult {

	#define XX(num, name, string) REQUEST_RESULT_##name = num,
	REQUEST_RESULT_MAP(XX)
	#undef XX

} RequestResult;

AUTH_PUBLIC const char *request_result_to_string (
	const RequestResult type
);

typedef struct AuthRequest {

	char auth_header[AUTH_HEADER_SIZE];
	size_t auth_header_len;

	char body[AUTH_REQUEST_SIZE];
	size_t body_len;
	
	char response[AUTH_RESPONSE_SIZE];
	size_t response_ptr;

} AuthRequest;

AUTH_PRIVATE void *auth_request_new (void);

AUTH_PRIVATE void auth_request_delete (void *request_ptr);

// a request is only sent when its header and its body were complete
AUTH_PRIVATE bool auth_request_is_valid (const AuthRequest *auth_request);

AUTH_PRIVATE void auth_request_create (
	AuthRequest *auth_request, const char *token, const char *source
);

AUTH_PRIVATE void auth_request_create_action (
	AuthRequest *auth_request, const char *token,
	const char *source, const char *action
);

AUTH_PRIVATE void auth_request_create_role (
	AuthRequest *auth_request,
	const char *token, const char *source,
	const char *action, const char *role
);

AUTH_PRIVATE void auth_request_create_service (
	AuthRequest *auth_request, const char *token,
	const char *source, const char *service
);

AUTH_PRIVATE void auth_request_create_single_permissions (
	AuthRequest *auth_request,
	const char *token, const char *source,
	const PermissionsType permissions_type,
	const char *resource, const char *permissions_action
);

AUTH_PRIVATE void auth_request_create_management_permissions (
	AuthRequest *auth_request, const char *token, const char *source,
	const PermissionsType permissions_type, const char *permissions_action
);

AUTH_PUBLIC RequestResult auth_request_authentication (
	const char *auth_service_address,
	AuthRequest *auth_request
);

#ifdef __cplusplus
}
#endif

#endif
