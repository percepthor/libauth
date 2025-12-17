#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <auth/auth.h>
#include <auth/permissions.h>
#include <auth/routes.h>

#include "test.h"

// the auth values of a route

// bugs this suite fixed:
// - the length of a value was the one snprintf () wanted to write, not the stored one
// - an action route created from NULL printed it with "%s"

#define TEST_ROUTES_ACTION			"tickets.create"
#define TEST_ROUTES_ROLE			"admin"

#define TEST_ROUTES_LONG_SIZE		1024

static void test_routes_token (void) {

	AuthRoute *route = auth_route_create ();
	test_check_ptr (route);

	test_check_unsigned_eq (route->auth_type, PERCEPTHOR_AUTH_TYPE_TOKEN, NULL);
	test_check_int_eq (route->action_len, 0, NULL);
	test_check_int_eq (route->role_len, 0, NULL);

	auth_route_print (route);
	auth_route_delete (route);

	auth_route_delete (NULL);
	auth_route_print (NULL);

}

static void test_routes_action (void) {

	AuthRoute *route = auth_route_create_action (TEST_ROUTES_ACTION);
	test_check_unsigned_eq (route->auth_type, PERCEPTHOR_AUTH_TYPE_ACTION, NULL);
	test_check_str_eq (route->action, TEST_ROUTES_ACTION, NULL);
	test_check_int_eq (route->action_len, (int) strlen (TEST_ROUTES_ACTION), NULL);
	auth_route_print (route);
	auth_route_delete (route);

	route = auth_route_create_action (NULL);
	test_check_str_empty (route->action);
	test_check_int_eq (route->action_len, 0, NULL);
	auth_route_delete (route);

}

static void test_routes_role (void) {

	AuthRoute *route = auth_route_create_role (TEST_ROUTES_ACTION, TEST_ROUTES_ROLE);
	test_check_unsigned_eq (route->auth_type, PERCEPTHOR_AUTH_TYPE_ROLE, NULL);
	test_check_str_eq (route->action, TEST_ROUTES_ACTION, NULL);
	test_check_str_eq (route->role, TEST_ROUTES_ROLE, NULL);
	test_check_int_eq (route->role_len, (int) strlen (TEST_ROUTES_ROLE), NULL);
	auth_route_print (route);
	auth_route_delete (route);

	route = auth_route_create_role (NULL, TEST_ROUTES_ROLE);
	test_check_int_eq (route->action_len, 0, NULL);
	test_check_str_eq (route->role, TEST_ROUTES_ROLE, NULL);
	auth_route_delete (route);

}

static void test_routes_service (void) {

	AuthRoute *route = auth_route_create_service ();
	test_check_unsigned_eq (route->auth_type, PERCEPTHOR_AUTH_TYPE_SERVICE, NULL);
	auth_route_delete (route);

}

static void test_routes_permissions (void) {

	AuthRoute *route = auth_route_create_permissions (
		PERCEPTHOR_AUTH_SCOPE_SINGLE, PERMISSIONS_TYPE_ORGANIZATION, TEST_ROUTES_ACTION
	);

	test_check_unsigned_eq (route->auth_type, PERCEPTHOR_AUTH_TYPE_PERMISSIONS, NULL);
	test_check_unsigned_eq (route->auth_scope, PERCEPTHOR_AUTH_SCOPE_SINGLE, NULL);
	test_check_unsigned_eq (route->permissions_type, PERMISSIONS_TYPE_ORGANIZATION, NULL);
	test_check_str_eq (route->permissions_action, TEST_ROUTES_ACTION, NULL);
	test_check_int_eq (route->permissions_action_len, (int) strlen (TEST_ROUTES_ACTION), NULL);
	auth_route_print (route);
	auth_route_delete (route);

	route = auth_route_create_permissions (
		PERCEPTHOR_AUTH_SCOPE_MANAGEMENT, PERMISSIONS_TYPE_PROJECT, NULL
	);

	test_check_int_eq (route->permissions_action_len, 0, NULL);
	auth_route_delete (route);

}

// a value longer than its field is truncated, and its length is the stored one
static void test_routes_truncated (void) {

	char long_value[TEST_ROUTES_LONG_SIZE];
	(void) memset (long_value, 'a', TEST_ROUTES_LONG_SIZE - 1);
	long_value[TEST_ROUTES_LONG_SIZE - 1] = '\0';

	AuthRoute *route = auth_route_create_role (long_value, long_value);
	test_check_int_eq (route->action_len, AUTH_ROUTE_ACTION_SIZE - 1, NULL);
	test_check_str_len (route->action, AUTH_ROUTE_ACTION_SIZE - 1, NULL);
	test_check_int_eq (route->role_len, AUTH_ROUTE_ROLE_SIZE - 1, NULL);
	auth_route_delete (route);

	route = auth_route_create_action (long_value);
	test_check_int_eq (route->action_len, AUTH_ROUTE_ACTION_SIZE - 1, NULL);
	auth_route_delete (route);

	route = auth_route_create_permissions (
		PERCEPTHOR_AUTH_SCOPE_SINGLE, PERMISSIONS_TYPE_ORGANIZATION, long_value
	);

	test_check_int_eq (route->permissions_action_len, AUTH_ROUTE_PERMISSIONS_SIZE - 1, NULL);
	auth_route_delete (route);

}

int main (int argc, char **argv) {

	(void) printf ("Testing ROUTES...\n");

	test_routes_token ();
	test_routes_action ();
	test_routes_role ();
	test_routes_service ();
	test_routes_permissions ();
	test_routes_truncated ();

	(void) printf ("Done!\n");

	return 0;

}
