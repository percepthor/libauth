#ifndef _PERCEPTHOR_AUTH_REQUESTS_H_
#define _PERCEPTHOR_AUTH_REQUESTS_H_

#include <stddef.h>
#include <stdbool.h>

#include "auth/auth.h"
#include "auth/config.h"
#include "auth/permissions.h"

/**
 * @file requests.h
 * @brief The requests of libauth to the auth service.
 *
 * Each authentication is a POST to the address of the AuthService with the token of
 * the request in its Authorization header and what the route requires as a JSON body.
 * A request that does not fit its buffers is never sent truncated: it fails closed.
 */

/** @brief The "Authorization: " header and the token of the request. */
#define AUTH_HEADER_SIZE				1024

/**
 * @brief The JSON body of a request: its keys, the source service and the resource and
 * the action of a single permissions route, even when every byte of them is escaped.
 */
#define AUTH_REQUEST_SIZE				4096

/** @brief The response buffer starts with this size and doubles while the answer grows. */
#define AUTH_RESPONSE_INITIAL_SIZE		1024

/** @brief The largest answer of the auth service, a larger one fails the request. */
#ifndef AUTH_RESPONSE_MAX_SIZE
#define AUTH_RESPONSE_MAX_SIZE			65536
#endif

/** @brief "X-Forwarded-For: " and the longest address of a client, an IPv6 with its zone. */
#define AUTH_FORWARDED_HEADER_SIZE		128

/** @brief "X-Request-Id: " and the longest request id of cerver. */
#define AUTH_REQUEST_ID_HEADER_SIZE		128

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

/**
 * @brief The result of a request to the auth service: NONE when it answered 200,
 * BAD_STATUS for any other status and FAILED when it could not be sent or answered.
 */
typedef enum RequestResult {

	#define XX(num, name, string) REQUEST_RESULT_##name = num,
	REQUEST_RESULT_MAP(XX)
	#undef XX

} RequestResult;

/**
 * @brief Returns the name of a request result.
 * @param type The result.
 * @return A static string, "None" for an unknown result.
 */
AUTH_PUBLIC const char *request_result_to_string (
	const RequestResult type
);

/**
 * @brief A request to the auth service and its answer.
 *
 * It is created on the stack with { 0 } and filled by one of the auth_request_create_* ()
 * functions; its answer is allocated by auth_request_authentication () and released
 * with auth_request_end ().
 */
typedef struct AuthRequest {

	char auth_header[AUTH_HEADER_SIZE];
	size_t auth_header_len;

	// the client of the request that is authenticated and its id,
	// "" when they are not known, then the header is not sent
	char forwarded_header[AUTH_FORWARDED_HEADER_SIZE];
	char request_id_header[AUTH_REQUEST_ID_HEADER_SIZE];

	char body[AUTH_REQUEST_SIZE];
	size_t body_len;

	// the answer of the auth service, NUL terminated, NULL before it answered
	char *response;
	size_t response_len;
	size_t response_size;

} AuthRequest;

AUTH_PRIVATE void *auth_request_new (void);

AUTH_PRIVATE void auth_request_delete (void *request_ptr);

// releases the answer of the auth service, the request can be sent again
AUTH_PRIVATE void auth_request_end (AuthRequest *auth_request);

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

// the auth service receives the address of the client (X-Forwarded-For)
// and the id of the request (X-Request-Id) that it authenticates,
// an empty or a NULL value is not sent
AUTH_PRIVATE void auth_request_set_client (
	AuthRequest *auth_request, const char *client_ip, const char *request_id
);

/**
 * @brief Sends a request to the auth service and keeps its answer.
 *
 * The answer (auth_request->response) is released with auth_request_end ().
 * @param auth_service_address The url of the auth service.
 * @param auth_request A complete request.
 * @return REQUEST_RESULT_NONE when the auth service answered 200.
 */
AUTH_PUBLIC RequestResult auth_request_authentication (
	const char *auth_service_address,
	AuthRequest *auth_request
);

#ifdef __cplusplus
}
#endif

#endif
