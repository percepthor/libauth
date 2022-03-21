#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "auth/auth.h"
#include "auth/permissions.h"

PermissionsAction *permissions_action_create (const char *action) {

	PermissionsAction *permissions_action = (PermissionsAction *) malloc (sizeof (PermissionsAction));
	if (permissions_action) {
		(void) strncpy (permissions_action->action, action, AUTH_ACTION_SIZE);
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
		(void) memset (permissions->organization, 0, AUTH_ORGANIZATION_SIZE);

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

const char *permissions_get_organization (const Permissions *permissions) {

	return permissions->organization;

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
		(void) printf ("Organization: %s\n", permissions->organization);

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
