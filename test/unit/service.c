#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <auth/service.h>

#include "test.h"

// the auth service of a cerver

// bugs this suite fixed:
// - the lengths were the ones snprintf () wanted to write, not the stored ones
// - auth_service_print () dereferenced NULL

#define TEST_SERVICE_ID				"507f1f77bcf86cd799439011"
#define TEST_SERVICE_NAME			"tickets"
#define TEST_SERVICE_ADDRESS		"http://auth:5020/api/auth/check"

#define TEST_SERVICE_LONG_SIZE		512

static void test_service_create (void) {

	AuthService *service = auth_service_create (TEST_SERVICE_ID, TEST_SERVICE_NAME, TEST_SERVICE_ADDRESS);
	test_check_ptr (service);

	test_check_str_eq (service->service_id, TEST_SERVICE_ID, NULL);
	test_check_int_eq (service->service_id_len, (int) strlen (TEST_SERVICE_ID), NULL);
	test_check_str_eq (service->service_name, TEST_SERVICE_NAME, NULL);
	test_check_int_eq (service->service_name_len, (int) strlen (TEST_SERVICE_NAME), NULL);
	test_check_str_eq (service->auth_service_address, TEST_SERVICE_ADDRESS, NULL);
	test_check_int_eq (service->auth_service_address_len, (int) strlen (TEST_SERVICE_ADDRESS), NULL);

	auth_service_print (service);
	auth_service_delete (service);

}

// the services create it without an id
static void test_service_create_without_values (void) {

	AuthService *service = auth_service_create (NULL, NULL, NULL);
	test_check_ptr (service);

	test_check_int_eq (service->service_id_len, 0, NULL);
	test_check_str_empty (service->service_id);
	test_check_int_eq (service->service_name_len, 0, NULL);
	test_check_int_eq (service->auth_service_address_len, 0, NULL);

	auth_service_print (service);
	auth_service_delete (service);

	auth_service_delete (NULL);
	auth_service_print (NULL);

}

static void test_service_truncated (void) {

	char long_value[TEST_SERVICE_LONG_SIZE];
	(void) memset (long_value, 'a', TEST_SERVICE_LONG_SIZE - 1);
	long_value[TEST_SERVICE_LONG_SIZE - 1] = '\0';

	AuthService *service = auth_service_create (long_value, long_value, long_value);

	test_check_int_eq (service->service_id_len, AUTH_SERVICE_ID_SIZE - 1, NULL);
	test_check_str_len (service->service_id, AUTH_SERVICE_ID_SIZE - 1, NULL);
	test_check_int_eq (service->service_name_len, AUTH_SERVICE_NAME_SIZE - 1, NULL);
	test_check_int_eq (service->auth_service_address_len, AUTH_SERVICE_ADDRESS_SIZE - 1, NULL);

	auth_service_delete (service);

}

int main (int argc, char **argv) {

	(void) printf ("Testing SERVICE...\n");

	test_service_create ();
	test_service_create_without_values ();
	test_service_truncated ();

	(void) printf ("Done!\n");

	return 0;

}
