#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <cerver/collections/dlist.h>

#include <auth/permissions.h>

#include "test.h"

// the permissions of a resource

// bugs this suite fixed:
// - permissions_has_action () and permissions_get_resource () dereferenced NULL
// - an action created from NULL was printed with "%s"

static void test_permissions_types (void) {

	test_check_str_eq (permissions_type_to_string (PERMISSIONS_TYPE_NONE), "None", NULL);
	test_check_str_eq (permissions_type_to_string (PERMISSIONS_TYPE_SERVICE), "Service", NULL);
	test_check_str_eq (permissions_type_to_string (PERMISSIONS_TYPE_ORGANIZATION), "Organization", NULL);
	test_check_str_eq (permissions_type_to_string (PERMISSIONS_TYPE_PROJECT), "Project", NULL);
	test_check_str_eq (permissions_type_to_string ((PermissionsType) 64), "None", NULL);

}

static void test_permissions_actions (void) {

	Permissions *permissions = permissions_create ();
	test_check_ptr (permissions);
	test_check_str_empty (permissions_get_resource (permissions));

	(void) dlist_insert_after (permissions->actions, dlist_end (permissions->actions), permissions_action_create ("read"));
	(void) dlist_insert_after (permissions->actions, dlist_end (permissions->actions), permissions_action_create (NULL));

	test_check_true (permissions_has_action (permissions, "read"));
	test_check_true (permissions_has_action (permissions, ""));
	test_check_false (permissions_has_action (permissions, "write"));
	test_check_false (permissions_has_action (permissions, NULL));

	permissions_print (permissions);
	permissions_delete (permissions);

}

static void test_permissions_without_values (void) {

	test_check_null_ptr (permissions_get_resource (NULL));
	test_check_false (permissions_has_action (NULL, "read"));

	permissions_print (NULL);
	permissions_delete (NULL);
	permissions_action_delete (NULL);

}

int main (int argc, char **argv) {

	(void) printf ("Testing PERMISSIONS...\n");

	test_permissions_types ();
	test_permissions_actions ();
	test_permissions_without_values ();

	(void) printf ("Done!\n");

	return 0;

}
