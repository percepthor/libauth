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

#include <features.h>

// to be used in the application
#define AUTH_EXPORT 			extern

// to be used by internal libauth methods
#define AUTH_PRIVATE			extern

// used by private methods but can be used by the application
#define AUTH_PUBLIC 			extern

#endif
