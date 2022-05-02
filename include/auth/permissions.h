#ifndef _PERCEPTHOR_PERMISSIONS_H_
#define _PERCEPTHOR_PERMISSIONS_H_

#include <stdbool.h>

#include <cerver/collections/dlist.h>

#include "auth/config.h"
#include "auth/types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PERMISSIONS_TYPE_MAP(XX)		\
	XX(0,  NONE,			None)			\
	XX(1,  SERVICE,			Service)		\
	XX(2,  ORGANIZATION,	Organization)	\
	XX(3,  PROJECT,			Project)

typedef enum PermissionsType {

	#define XX(num, name, string) PERMISSIONS_TYPE_##name = num,
	PERMISSIONS_TYPE_MAP(XX)
	#undef XX

} PermissionsType;

AUTH_PUBLIC const char *permissions_type_to_string (
	const PermissionsType scope
);

typedef struct PermissionsAction {

	unsigned int action_len;
	char action[AUTH_ACTION_SIZE];

} PermissionsAction;

AUTH_PRIVATE PermissionsAction *permissions_action_create (const char *action);

AUTH_PRIVATE void permissions_action_delete (void *permissions_action_ptr);

struct _Permissions {

	char resource[AUTH_RESOURCE_SIZE];

	DoubleList *actions;

};

typedef struct _Permissions Permissions;

AUTH_PRIVATE void permissions_delete (void *permissions_ptr);

AUTH_EXPORT const char *permissions_get_resource (
	const Permissions *permissions
);

AUTH_PRIVATE Permissions *permissions_create (void);

AUTH_PUBLIC void permissions_print (const Permissions *permissions);

AUTH_EXPORT bool permissions_has_action (
	const Permissions *permissions, const char *action
);

#ifdef __cplusplus
}
#endif

#endif