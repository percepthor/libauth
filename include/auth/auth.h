#ifndef _PERCEPTHOR_AUTH_H_
#define _PERCEPTHOR_AUTH_H_

#include <stdint.h>

#include "auth/auth.h"
#include "auth/config.h"

#define AUTH_ID_SIZE		32

#ifdef __cplusplus
extern "C" {
#endif

struct _HttpReceive;
struct _HttpRequest;

typedef struct PercepthorAuth {

	char service_id[AUTH_ID_SIZE];

	char token[AUTH_ID_SIZE];
	char permissions[AUTH_ID_SIZE];
	char user[AUTH_ID_SIZE];

	int64_t mask;

} PercepthorAuth;

AUTH_EXPORT unsigned int percepthor_custom_authentication_handler (
	const struct _HttpReceive *http_receive,
	const struct _HttpRequest *request
);

#ifdef __cplusplus
}
#endif

#endif