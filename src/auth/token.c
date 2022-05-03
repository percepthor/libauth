#include <stdio.h>

#include "auth/token.h"

const char *percepthor_token_type_to_string (const PercepthorTokenType type) {

	switch (type) {
		#define XX(num, name, string) case PERCEPTHOR_TOKEN_TYPE_##name: return #string;
		PERCEPTHOR_TOKEN_TYPE_MAP(XX)
		#undef XX
	}

	return percepthor_token_type_to_string (PERCEPTHOR_TOKEN_TYPE_NONE);

}

void percepthor_token_print (const AuthToken *auth_token) {

	(void) printf ("Auth Token:\n");

	(void) printf ("\tid: %s\n", auth_token->id);

	(void) printf (
		"\ttype: %s\n", percepthor_token_type_to_string (auth_token->type)
	);

	(void) printf ("\torganization: %s\n", auth_token->organization);
	(void) printf ("\tuser: %s\n", auth_token->user);

	// values based on type
	switch (auth_token->type) {
		case PERCEPTHOR_TOKEN_TYPE_NONE: break;

		case PERCEPTHOR_TOKEN_TYPE_NORMAL:
		case PERCEPTHOR_TOKEN_TYPE_TEMPORARY:
		case PERCEPTHOR_TOKEN_TYPE_QUANTITY:
			(void) printf ("\tpermissions: %s\n", auth_token->permissions);
			break;

		case PERCEPTHOR_TOKEN_TYPE_USER:
			(void) printf ("\trole: %s\n", auth_token->role);
			(void) printf ("\tusername: %s\n", auth_token->username);
			break;

		default: break;
	}

}
