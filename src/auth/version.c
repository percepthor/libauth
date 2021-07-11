#include <cerver/utils/log.h>

#include "auth/version.h"

// print full libauth version information
void percepthor_libauth_version_print_full (void) {

	cerver_log_both (
		LOG_TYPE_NONE, LOG_TYPE_NONE,
		"\nPercepthor libauth Version: %s", PERCEPTHOR_LIBAUTH_VERSION_NAME
	);

	cerver_log_both (
		LOG_TYPE_NONE, LOG_TYPE_NONE,
		"Release Date & time: %s - %s", PERCEPTHOR_LIBAUTH_VERSION_DATE, PERCEPTHOR_LIBAUTH_VERSION_TIME
	);

	cerver_log_both (
		LOG_TYPE_NONE, LOG_TYPE_NONE,
		"Author: %s\n", PERCEPTHOR_LIBAUTH_VERSION_AUTHOR
	);

}

// print the version id
void percepthor_libauth_version_print_version_id (void) {

	cerver_log_both (
		LOG_TYPE_NONE, LOG_TYPE_NONE,
		"\nPercepthor libauth Version ID: %s\n", PERCEPTHOR_LIBAUTH_VERSION
	);

}

// print the version name
void percepthor_libauth_version_print_version_name (void) {

	cerver_log_both (
		LOG_TYPE_NONE, LOG_TYPE_NONE,
		"\nPercepthor libauth Version: %s\n", PERCEPTHOR_LIBAUTH_VERSION_NAME
	);

}
