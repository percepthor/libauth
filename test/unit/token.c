#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <auth/token.h>
#include <auth/version.h>

#include "test.h"

// the token types, the token print and the version print

// bugs this suite fixed:
// - percepthor_token_print () dereferenced NULL

static void test_token_types (void) {

	test_check_str_eq (percepthor_token_type_to_string (PERCEPTHOR_TOKEN_TYPE_NONE), "None", NULL);
	test_check_str_eq (percepthor_token_type_to_string (PERCEPTHOR_TOKEN_TYPE_NORMAL), "Normal", NULL);
	test_check_str_eq (percepthor_token_type_to_string (PERCEPTHOR_TOKEN_TYPE_TEMPORARY), "Temporary", NULL);
	test_check_str_eq (percepthor_token_type_to_string (PERCEPTHOR_TOKEN_TYPE_QUANTITY), "Quantity", NULL);
	test_check_str_eq (percepthor_token_type_to_string (PERCEPTHOR_TOKEN_TYPE_USER), "User", NULL);
	test_check_str_eq (percepthor_token_type_to_string ((PercepthorTokenType) 64), "None", NULL);

}

static void test_token_print (void) {

	AuthToken token = { 0 };

	for (unsigned int type = PERCEPTHOR_TOKEN_TYPE_NONE; type <= PERCEPTHOR_TOKEN_TYPE_USER; type++) {
		token.type = (PercepthorTokenType) type;
		percepthor_token_print (&token);
	}

	percepthor_token_print (NULL);

}

static void test_version_print (void) {

	percepthor_libauth_version_print_full ();
	percepthor_libauth_version_print_version_id ();
	percepthor_libauth_version_print_version_name ();

}

int main (int argc, char **argv) {

	(void) printf ("Testing TOKEN...\n");

	test_token_types ();
	test_token_print ();
	test_version_print ();

	(void) printf ("Done!\n");

	return 0;

}
