#include "auth/token.h"

const char *percepthor_token_type_to_string (const PercepthorTokenType type) {

	switch (type) {
		#define XX(num, name, string) case PERCEPTHOR_TOKEN_TYPE_##name: return #string;
		PERCEPTHOR_TOKEN_TYPE_MAP(XX)
		#undef XX
	}

	return percepthor_token_type_to_string (PERCEPTHOR_TOKEN_TYPE_NONE);

}
