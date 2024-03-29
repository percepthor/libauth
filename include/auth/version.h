#ifndef _PERCEPTHOR_AUTH_VERSION_H_
#define _PERCEPTHOR_AUTH_VERSION_H_

#include "auth/config.h"

#define PERCEPTHOR_AUTH_VERSION				"0.4.4"
#define PERCEPTHOR_AUTH_VERSION_NAME		"Version 0.4.4"
#define PERCEPTHOR_AUTH_VERSION_DATE		"24/09/2022"
#define PERCEPTHOR_AUTH_VERSION_TIME		"00:02 CST"
#define PERCEPTHOR_AUTH_VERSION_AUTHOR		"Erick Salas"

#ifdef __cplusplus
extern "C" {
#endif

// print full percepthor libauth version information
AUTH_PUBLIC void percepthor_libauth_version_print_full (void);

// print the version id
AUTH_PUBLIC void percepthor_libauth_version_print_version_id (void);

// print the version name
AUTH_PUBLIC void percepthor_libauth_version_print_version_name (void);

#ifdef __cplusplus
}
#endif

#endif
