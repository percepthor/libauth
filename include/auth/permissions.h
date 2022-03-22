#ifndef _PERCEPTHOR_PERMISSIONS_H_
#define _PERCEPTHOR_PERMISSIONS_H_

#include <stdbool.h>

#include <cerver/collections/dlist.h>

#include "auth/auth.h"
#include "auth/config.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct PermissionsAction {

	unsigned int action_len;
	char action[AUTH_ACTION_SIZE];

} PermissionsAction;

AUTH_PRIVATE PermissionsAction *permissions_action_create (const char *action);

AUTH_PRIVATE void permissions_action_delete (void *permissions_action_ptr);

struct _Permissions {

	char organization[AUTH_ORGANIZATION_SIZE];

	DoubleList *actions;

};

typedef struct _Permissions Permissions;

AUTH_PRIVATE void permissions_delete (void *permissions_ptr);

AUTH_EXPORT const char *permissions_get_organization (
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