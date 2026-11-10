#ifndef _PERCEPTHOR_AUTH_TYPES_H_
#define _PERCEPTHOR_AUTH_TYPES_H_

/**
 * @file types.h
 * @brief The sizes of the values that libauth keeps, with their terminating null byte.
 */

/** @brief An id of the auth service, like an ObjectId (24 characters). */
#define AUTH_ID_SIZE				32

/** @brief A resource of a permissions route. */
#define AUTH_RESOURCE_SIZE			256

/** @brief An action of a route or of a permissions. */
#define AUTH_ACTION_SIZE			256

#endif
