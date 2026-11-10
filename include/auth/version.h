#ifndef _PERCEPTHOR_AUTH_VERSION_H_
#define _PERCEPTHOR_AUTH_VERSION_H_

#include "auth/config.h"

/**
 * @file version.h
 * @brief The version of libauth.
 */

#define PERCEPTHOR_AUTH_VERSION				"0.5"
#define PERCEPTHOR_AUTH_VERSION_NAME		"Version 0.5"
#define PERCEPTHOR_AUTH_VERSION_DATE		"19/12/2025"
#define PERCEPTHOR_AUTH_VERSION_TIME		"19:07 CST"
#define PERCEPTHOR_AUTH_VERSION_AUTHOR		"Erick Salas"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Prints the version of libauth with its date and its author. */
AUTH_PUBLIC void percepthor_libauth_version_print_full (void);

/** @brief Prints the version id of libauth. */
AUTH_PUBLIC void percepthor_libauth_version_print_version_id (void);

/** @brief Prints the version name of libauth. */
AUTH_PUBLIC void percepthor_libauth_version_print_version_name (void);

#ifdef __cplusplus
}
#endif

#endif
