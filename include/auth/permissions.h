#ifndef _PERCEPTHOR_PERMISSIONS_H_
#define _PERCEPTHOR_PERMISSIONS_H_

#include <stdbool.h>

#include <cerver/collections/dlist.h>

#include "auth/config.h"
#include "auth/types.h"

/**
 * @file permissions.h
 * @brief The permissions of a user over the resources of a type, as the auth service
 * answers them to a management permissions route.
 */

#ifdef __cplusplus
extern "C" {
#endif

#define PERMISSIONS_TYPE_MAP(XX)		\
	XX(0,  NONE,			None)			\
	XX(1,  SERVICE,			Service)		\
	XX(2,  ORGANIZATION,	Organization)	\
	XX(3,  PROJECT,			Project)

/** @brief The type of the resources of a permissions route. */
typedef enum PermissionsType {

	#define XX(num, name, string) PERMISSIONS_TYPE_##name = num,
	PERMISSIONS_TYPE_MAP(XX)
	#undef XX

} PermissionsType;

/**
 * @brief Returns the name of a permissions type.
 * @param type The type.
 * @return A static string, "None" for an unknown type.
 */
AUTH_PUBLIC const char *permissions_type_to_string (
	const PermissionsType type
);

/** @brief An action allowed over a resource. */
typedef struct PermissionsAction {

	unsigned int action_len;
	char action[AUTH_ACTION_SIZE];

} PermissionsAction;

AUTH_PRIVATE PermissionsAction *permissions_action_create (const char *action);

AUTH_PRIVATE void permissions_action_delete (void *permissions_action_ptr);

/** @brief A resource and the actions that the user can do over it. */
struct _Permissions {

	char resource[AUTH_RESOURCE_SIZE];

	DoubleList *actions;

};

typedef struct _Permissions Permissions;

AUTH_PRIVATE void permissions_delete (void *permissions_ptr);

/**
 * @brief Returns the resource of the permissions.
 * @param permissions The permissions, can be NULL.
 * @return The resource, NULL for NULL.
 */
AUTH_EXPORT const char *permissions_get_resource (
	const Permissions *permissions
);

AUTH_PRIVATE Permissions *permissions_create (void);

/**
 * @brief Prints the resource and the actions of the permissions.
 * @param permissions The permissions, NULL does nothing.
 */
AUTH_PUBLIC void permissions_print (const Permissions *permissions);

/**
 * @brief Checks if the permissions allow an action.
 * @param permissions The permissions, can be NULL.
 * @param action The action.
 * @return true when the action is one of the actions of the resource.
 */
AUTH_EXPORT bool permissions_has_action (
	const Permissions *permissions, const char *action
);

#ifdef __cplusplus
}
#endif

#endif
