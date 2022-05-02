#ifndef _PERCEPTHOR_AUTH_H_
#define _PERCEPTHOR_AUTH_H_

#include <stdbool.h>
#include <stdint.h>

#include <cerver/collections/dlist.h>

#include "auth/config.h"
#include "auth/permissions.h"
#include "auth/types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct _HttpReceive;
struct _HttpRequest;

struct _Permissions;

#define PERCEPTHOR_AUTH_TYPE_MAP(XX)		\
	XX(0,  NONE,      		None)			\
	XX(1,  ACTION,      	Action)			\
	XX(2,  ROLE,  			Role)			\
	XX(3,  SERVICE,			Service)		\
	XX(4,  PERMISSIONS,		Permissions)	\
	XX(5,  MULTIPLE,		Multiple)		\
	XX(6,  COMPLETE,		Complete)

typedef enum PercepthorAuthType {

	#define XX(num, name, string) PERCEPTHOR_AUTH_TYPE_##name = num,
	PERCEPTHOR_AUTH_TYPE_MAP(XX)
	#undef XX

} PercepthorAuthType;

AUTH_PUBLIC const char *percepthor_auth_type_to_string (
	const PercepthorAuthType type
);

typedef struct PercepthorAuth {

	PercepthorAuthType type;

	char service_id[AUTH_ID_SIZE];

	char organization[AUTH_ORGANIZATION_SIZE];
	char project[AUTH_PROJECT_SIZE];
	char action[AUTH_ACTION_SIZE];

	bool super_admin;

	DoubleList *permissions;
	ListElement *next_permissions;

	char token[AUTH_ID_SIZE];
	char user[AUTH_ID_SIZE];

	int64_t mask;

} PercepthorAuth;

AUTH_PUBLIC void percepthor_auth_delete (void *auth_ptr);

AUTH_EXPORT const PercepthorAuthType percepthor_auth_get_type (
	const PercepthorAuth *percepthor_auth
);

AUTH_EXPORT const char *percepthor_auth_get_organization (
	const PercepthorAuth *percepthor_auth
);

AUTH_EXPORT const char *percepthor_auth_get_project (
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

extern bool percepthor_auth_permissions_iter_start (PercepthorAuth *percepthor_auth);

extern const struct _Permissions *percepthor_auth_permissions_iter_get_next (
	PercepthorAuth *percepthor_auth
);

AUTH_PUBLIC PercepthorAuth *percepthor_auth_create (const PercepthorAuthType type);

AUTH_EXPORT unsigned int percepthor_single_authentication (
	const struct _HttpReceive *http_receive,
	const struct _HttpRequest *request,
	const char *organization, const char *action
);

AUTH_EXPORT unsigned int percepthor_management_authentication (
	const struct _HttpReceive *http_receive,
	const struct _HttpRequest *request
);

AUTH_EXPORT unsigned int percepthor_custom_authentication_handler (
	const struct _HttpReceive *http_receive,
	const struct _HttpRequest *request
);

#ifdef __cplusplus
}
#endif

#endif