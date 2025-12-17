#ifndef _AUTH_TESTS_FUZZ_H_
#define _AUTH_TESTS_FUZZ_H_

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// the input as a string of the exact size, so a read past it is found
static inline char *fuzz_string (const uint8_t *data, const size_t size) {

	char *string = (char *) malloc (size + 1);
	if (string) {
		(void) memcpy (string, data, size);
		string[size] = '\0';
	}

	return string;

}

#endif
