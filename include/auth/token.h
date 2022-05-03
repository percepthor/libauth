#ifndef _PERCEPTHOR_AUTH_TOKEN_H_
#define _PERCEPTHOR_AUTH_TOKEN_H_

#include <stddef.h>

#include "auth/config.h"
#include "auth/types.h"

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

typedef enum PercepthorTokenType {

	#define XX(num, name, string) PERCEPTHOR_TOKEN_TYPE_##name = num,
	PERCEPTHOR_TOKEN_TYPE_MAP(XX)
	#undef XX

} PercepthorTokenType;

AUTH_PUBLIC const char *percepthor_token_type_to_string (
	const PercepthorTokenType type
);

typedef struct AuthToken {

	char id[AUTH_ID_SIZE];

	PercepthorTokenType type;

	char organization[AUTH_ID_SIZE];

	char permissions[AUTH_ID_SIZE];

	char role[AUTH_ID_SIZE];
	char user[AUTH_ID_SIZE];
	char username[AUTH_TOKEN_USERNAME_SIZE];

} AuthToken;

#ifdef __cplusplus
}
#endif

#endif
