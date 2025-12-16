#ifndef _PERCEPTHOR_AUTH_CONFIG_H_
#define _PERCEPTHOR_AUTH_CONFIG_H_

#ifndef _GNU_SOURCE
	#define _GNU_SOURCE
#endif

#ifndef __USE_GNU
	#define __USE_GNU
#endif

#ifndef __USE_POSIX199309
	#define __USE_POSIX199309
#endif

#ifndef _XOPEN_SOURCE
	#define _XOPEN_SOURCE 700
#endif

#ifdef __linux__
	#include <features.h>
#endif

/**
 * @file config.h
 * @brief The export macros of libauth.
 *
 * libauth is compiled with -fvisibility=hidden: libauth.so only exports the
 * functions marked with AUTH_EXPORT or AUTH_PUBLIC, the AUTH_PRIVATE ones are
 * only visible inside the library and to its tests, that link its objects.
 */

#if defined (__GNUC__) || defined (__clang__)
	#define AUTH_VISIBLE			__attribute__ ((visibility ("default")))
	#define AUTH_HIDDEN				__attribute__ ((visibility ("hidden")))
#else
	#define AUTH_VISIBLE
	#define AUTH_HIDDEN
#endif

/** @brief A function of the API, to be used by the application. */
#define AUTH_EXPORT 			extern AUTH_VISIBLE

/** @brief An internal function of libauth, never exported by libauth.so. */
#define AUTH_PRIVATE			extern AUTH_HIDDEN

/** @brief A function that libauth uses internally and the application can also use. */
#define AUTH_PUBLIC 			extern AUTH_VISIBLE

#endif
