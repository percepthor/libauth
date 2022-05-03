#ifndef _PERCEPTHOR_AUTH_H_
#define _PERCEPTHOR_AUTH_H_

#include <stdbool.h>
#include <stdint.h>

#include <cerver/collections/dlist.h>

#include "auth/config.h"
#include "auth/permissions.h"
#include "auth/token.h"
#include "auth/types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct _HttpReceive;
struct _HttpRequest;

struct _Permissions;

#define PERCEPTHOR_AUTH_TYPE_MAP(XX)		\
	XX(0,  NONE,      		None)			\
	XX(1,  TOKEN,      		Token)			\
	XX(2,  ACTION,      	Action)			\
	XX(3,  ROLE,  			Role)			\
	XX(4,  SERVICE,			Service)		\
	XX(5,  PERMISSIONS,		Permissions)	\
	XX(6,  MULTIPLE,		Multiple)		\
	XX(7,  COMPLETE,		Complete)

typedef enum PercepthorAuthType {

	#define XX(num, name, string) PERCEPTHOR_AUTH_TYPE_##name = num,
	PERCEPTHOR_AUTH_TYPE_MAP(XX)
	#undef XX

} PercepthorAuthType;

AUTH_PUBLIC const char *percepthor_auth_type_to_string (
	const PercepthorAuthType type
);

#define PERCEPTHOR_AUTH_SCOPE_MAP(XX)	\
	XX(0,  NONE,      	None)			\
	XX(1,  SINGLE,      Single)			\
	XX(2,  MANAGEMENT,  Management)

typedef enum PercepthorAuthScope {

	#define XX(num, name, string) PERCEPTHOR_AUTH_SCOPE_##name = num,
	PERCEPTHOR_AUTH_SCOPE_MAP(XX)
	#undef XX

} PercepthorAuthScope;

AUTH_PUBLIC const char *percepthor_auth_scope_to_string (
	const PercepthorAuthScope scope
);

typedef struct PercepthorAuth {

	PercepthorAuthType type;
	PercepthorAuthScope scope;

	char service[AUTH_ID_SIZE];

	PermissionsType permissions_type;
	char resource[AUTH_RESOURCE_SIZE];
	char action[AUTH_ACTION_SIZE];

	bool super_admin;

	DoubleList *permissions;
	ListElement *next_permissions;

	AuthToken token;

	int64_t mask;

} PercepthorAuth;

AUTH_PUBLIC void percepthor_auth_delete (void *auth_ptr);

AUTH_EXPORT const PercepthorAuthType percepthor_auth_get_type (
	const PercepthorAuth *percepthor_auth
);

AUTH_EXPORT const PercepthorAuthScope percepthor_auth_get_scope (
	const PercepthorAuth *percepthor_auth
);

AUTH_EXPORT const char *percepthor_auth_get_resource (
	const PercepthorAuth *percepthor_auth
);

AUTH_EXPORT const char *percepthor_auth_get_action (
	const PercepthorAuth *percepthor_auth
);

AUTH_EXPORT const bool percepthor_auth_get_admin (
	const PercepthorAuth *percepthor_auth
);

AUTH_EXPORT DoubleList *percepthor_auth_get_permissions (
	const PercepthorAuth *percepthor_auth
);

AUTH_EXPORT bool percepthor_auth_permissions_iter_start (PercepthorAuth *percepthor_auth);

AUTH_EXPORT const struct _Permissions *percepthor_auth_permissions_iter_get_next (
	PercepthorAuth *percepthor_auth
);

AUTH_EXPORT const char *percepthor_auth_get_token_id (
	const PercepthorAuth *percepthor_auth
);

AUTH_EXPORT const PercepthorTokenType percepthor_auth_get_token_type (
	const PercepthorAuth *percepthor_auth
);

AUTH_EXPORT const char *percepthor_auth_get_token_organization (
	const PercepthorAuth *percepthor_auth
);

AUTH_EXPORT const char *percepthor_auth_get_token_permissions (
	const PercepthorAuth *percepthor_auth
);

AUTH_EXPORT const char *percepthor_auth_get_token_role (
	const PercepthorAuth *percepthor_auth
);

AUTH_EXPORT const char *percepthor_auth_get_token_user (
	const PercepthorAuth *percepthor_auth
);

AUTH_EXPORT const char *percepthor_auth_get_token_username (
	const PercepthorAuth *percepthor_auth
);

AUTH_EXPORT const int64_t percepthor_auth_get_mask (
	const PercepthorAuth *percepthor_auth
);

AUTH_PUBLIC PercepthorAuth *percepthor_auth_create (const PercepthorAuthType type);

AUTH_EXPORT unsigned int percepthor_single_authentication (
	const struct _HttpReceive *http_receive,
	const struct _HttpRequest *request,
	const PermissionsType permissions_type,
	const char *resource, const char *action
);

AUTH_EXPORT unsigned int percepthor_custom_authentication_handler (
	const struct _HttpReceive *http_receive,
	const struct _HttpRequest *request
);

#ifdef __cplusplus
}
#endif

#endif