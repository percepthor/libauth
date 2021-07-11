#ifndef _PERCEPTHOR_AUTH_H_
#define _PERCEPTHOR_AUTH_H_

#include <stdint.h>

#define AUTH_ID_SIZE		32

#ifdef __cplusplus
extern "C" {
#endif

typedef struct PercepthorAuth {

	char service_id[AUTH_ID_SIZE];

	char token[AUTH_ID_SIZE];
	char permissions[AUTH_ID_SIZE];
	char user[AUTH_ID_SIZE];

	int64_t mask;

} PercepthorAuth;

#ifdef __cplusplus
}
#endif

#endif