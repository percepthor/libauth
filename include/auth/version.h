#ifndef _PERCEPTHOR_AUTH_VERSION_H_
#define _PERCEPTHOR_AUTH_VERSION_H_

#define PERCEPTHOR_AUTH_VERSION				"0.2"
#define PERCEPTHOR_AUTH_VERSION_NAME		"Version 0.2"
#define PERCEPTHOR_AUTH_VERSION_DATE		"21/03/2022"
#define PERCEPTHOR_AUTH_VERSION_TIME		"20:45 CST"
#define PERCEPTHOR_AUTH_VERSION_AUTHOR		"Erick Salas"

#ifdef __cplusplus
extern "C" {
#endif

// print full percepthor libauth version information
extern void percepthor_libauth_version_print_full (void);

// print the version id
extern void percepthor_libauth_version_print_version_id (void);

// print the version name
extern void percepthor_libauth_version_print_version_name (void);

#ifdef __cplusplus
}
#endif

#endif