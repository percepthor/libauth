#ifndef _PERCEPTHOR_AUTH_TOKEN_H_
#define _PERCEPTHOR_AUTH_TOKEN_H_

#include <stddef.h>

#include "auth/config.h"
#include "auth/types.h"

/**
 * @file token.h
 * @brief The values of the token of an authenticated request, as the auth service answers them.
 */

#define AUTH_TOKEN_USERNAME_SIZE		128

#ifdef __cplusplus
extern "C" {
#endif

#define PERCEPTHOR_TOKEN_TYPE_MAP(XX)		\
	XX(0,  NONE,      		None)			\
	XX(1,  NORMAL,      	Normal)			\
	XX(2,  TEMPORARY,      	Temporary)		\
	XX(3,  QUANTITY,  		Quantity)		\
	XX(4,  USER,			User)

/** @brief The type of a token, a value that is not one of these is read as NONE. */
typedef enum PercepthorTokenType {

	#define XX(num, name, string) PERCEPTHOR_TOKEN_TYPE_##name = num,
	PERCEPTHOR_TOKEN_TYPE_MAP(XX)
	#undef XX

} PercepthorTokenType;

/**
 * @brief Returns the name of a token type.
 * @param type The type.
 * @return A static string, "None" for an unknown type.
 */
AUTH_PUBLIC const char *percepthor_token_type_to_string (
	const PercepthorTokenType type
);

/**
 * @brief The values of a token; a value longer than its buffer is truncated.
 */
typedef struct AuthToken {

	char id[AUTH_ID_SIZE];

	PercepthorTokenType type;

	char organization[AUTH_ID_SIZE];

	char permissions[AUTH_ID_SIZE];

	char role[AUTH_ID_SIZE];
	char user[AUTH_ID_SIZE];
	char username[AUTH_TOKEN_USERNAME_SIZE];

} AuthToken;

/**
 * @brief Prints the values of a token.
 * @param auth_token The token, NULL does nothing.
 */
AUTH_PUBLIC void percepthor_token_print (const AuthToken *auth_token);

#ifdef __cplusplus
}
#endif

#endif
