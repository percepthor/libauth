#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "auth/auth.h"
#include "auth/permissions.h"

const char *permissions_type_to_string (const PermissionsType type) {

	switch (type) {
		#define XX(num, name, string) case PERMISSIONS_TYPE_##name: return #string;
		PERMISSIONS_TYPE_MAP(XX)
		#undef XX
	}

	return permissions_type_to_string (PERMISSIONS_TYPE_NONE);

}

PermissionsAction *permissions_action_create (const char *action) {

	PermissionsAction *permissions_action = (PermissionsAction *) malloc (sizeof (PermissionsAction));
	if (permissions_action) {
		(void) snprintf (permissions_action->action, AUTH_ACTION_SIZE, "%s", action);
		permissions_action->action_len = strlen (permissions_action->action);
	}

	return permissions_action;

}

void permissions_action_delete (void *permissions_action_ptr) {

	if (permissions_action_ptr) {
		free (permissions_action_ptr);
	}

}

static Permissions *permissions_new (void) {

	Permissions *permissions = (Permissions *) malloc (sizeof (Permissions));
	if (permissions) {
		(void) memset (permissions->resource, 0, AUTH_RESOURCE_SIZE);

		permissions->actions = NULL;
	}

	return permissions;

}

void permissions_delete (void *permissions_ptr) {

	if (permissions_ptr) {
		Permissions *permissions = (Permissions *) permissions_ptr;

		dlist_delete (permissions->actions);

		free (permissions_ptr);
	}

}

const char *permissions_get_resource (const Permissions *permissions) {

	return permissions->resource;

}

Permissions *permissions_create (void) {

	Permissions *permissions = permissions_new ();
	if (permissions) {
		permissions->actions = dlist_init (permissions_action_delete, NULL);
	}

	return permissions;

}

void permissions_print (const Permissions *permissions) {

	if (permissions) {
		(void) printf ("Resource: %s\n", permissions->resource);

		(void) printf ("Actions: %lu\n", permissions->actions->size);

		ListElement *le = NULL;
		dlist_for_each (permissions->actions, le) {
			(void) printf ("\t%s\n", ((PermissionsAction *) le->data)->action);
		}
	}

}

bool permissions_has_action (
	const Permissions *permissions, const char *action
) {

	bool result = false;

	ListElement *le = NULL;
	PermissionsAction *permissions_action = NULL;
	dlist_for_each (permissions->actions, le) {
		permissions_action = (PermissionsAction *) le->data;

		if (!strcmp (permissions_action->action, action)) {
			result = true;
			break;
		}
	}

	return result;

}
