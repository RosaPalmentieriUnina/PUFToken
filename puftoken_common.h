#ifndef PUFTOKEN_COMMON_H
#define PUFTOKEN_COMMON_H

#include <inttypes.h>
#include <stddef.h>

/*
 * Common scalar types 
*/

/**
 * Identifier of a protocol actor.
 *
 * Two bytes are sufficient for the proof of concept and keep the
 * representation aligned with the GK-PHEMAP reference implementation.
 */
typedef uint16_t puftoken_id_t;

/**
 * Link of the PUF chain.
 */
typedef uint32_t puf_link_t;

/**
 * Type used for ATS, RL, NRL and token counters.
 */
typedef uint16_t token_count_t;

/*
 * Proof-of-concept limits
 */

/**
 * Number of tokens generated during the simulated initialization.
 *
 * The protocol description uses 100 tokens as its reference example.
 */
#define PUFTOKEN_MAX_ISSUED_TOKENS 100U

/**
 * Maximum number of tokens transferable in a single transaction.
 *
 * This is a temporary implementation limit for the first proof of concept.
 * It can be changed later without modifying the packet logic.
 */
#define PUFTOKEN_MAX_TOKENS_PER_SPEND PUFTOKEN_MAX_ISSUED_TOKENS


/*
 * Cryptographic representation
 */

/**
 * The first proof of concept will use an AES-128-compatible representation.
 */
#define PUFTOKEN_KEY_SIZE 16U
#define PUFTOKEN_BLOCK_SIZE 16U

/**
 * Session key RA or RB.
 */
typedef struct
{
    uint8_t bytes[PUFTOKEN_KEY_SIZE];
} puftoken_key_t;

/**
 * Encrypted block.
 *
 * It will be used both for protected links and for values produced
 * by the simulated Bank.
 */
typedef struct
{
    uint8_t bytes[PUFTOKEN_BLOCK_SIZE];
} puftoken_block_t;


/*
 * Protocol message codes
 */

typedef enum
{
    PUFTOKEN_SPEND_REQUEST,
    PUFTOKEN_SPEND_AUTH_RESULT,
    PUFTOKEN_TOKEN_BATCH,
    PUFTOKEN_SPEND_RESULT
} puftoken_message_t;


/*
 * Status values transported inside protocol messages
 */

typedef enum
{
    PUFTOKEN_STATUS_OK,
    PUFTOKEN_STATUS_INTEGRITY_FAIL,
    PUFTOKEN_STATUS_INVALID_AMOUNT,
    PUFTOKEN_STATUS_ACCEPT,
    PUFTOKEN_STATUS_INVALID_TOKEN
} puftoken_status_t;


/*
 * Internal return values
 */

typedef enum
{
    PUFTOKEN_RET_OK,
    PUFTOKEN_RET_INVALID_ARGUMENT,
    PUFTOKEN_RET_INVALID_STATE,
    PUFTOKEN_RET_INVALID_PACKET,
    PUFTOKEN_RET_BUFFER_TOO_SMALL,
    PUFTOKEN_RET_CRYPTO_ERROR
} puftoken_ret_t;


/*
 * Logical field sizes
 */

#define PUFTOKEN_MESSAGE_TYPE_SIZE sizeof(uint8_t)
#define PUFTOKEN_ID_SIZE sizeof(puftoken_id_t)
#define PUFTOKEN_TOKEN_COUNT_SIZE sizeof(token_count_t)
#define PUFTOKEN_STATUS_SIZE sizeof(uint8_t)


/**
 * Plaintext representation of Q || RL.
 */
#define PUFTOKEN_STATE_PLAINTEXT_SIZE \
    (sizeof(puf_link_t) + sizeof(token_count_t))


/*
 * Packet sizes
 *
 * SPEND_REQUEST:
 * TYPE | DEVICE_ID | ATS | ENC_RA(Q || RL) | ENC_BANK(Q || RL)
 */
#define PUFTOKEN_SPEND_REQUEST_SIZE \
    (PUFTOKEN_MESSAGE_TYPE_SIZE + \
     PUFTOKEN_ID_SIZE + \
     PUFTOKEN_TOKEN_COUNT_SIZE + \
     PUFTOKEN_BLOCK_SIZE + \
     PUFTOKEN_BLOCK_SIZE)

/**
 * SPEND_AUTH_RESULT:
 * TYPE | PS_ID | STATUS
 *
 * NRL is appended only when STATUS is PUFTOKEN_STATUS_OK.
 */
#define PUFTOKEN_SPEND_AUTH_RESULT_BASE_SIZE \
    (PUFTOKEN_MESSAGE_TYPE_SIZE + \
     PUFTOKEN_ID_SIZE + \
     PUFTOKEN_STATUS_SIZE)

#define PUFTOKEN_SPEND_AUTH_RESULT_OK_SIZE \
    (PUFTOKEN_SPEND_AUTH_RESULT_BASE_SIZE + \
     PUFTOKEN_TOKEN_COUNT_SIZE)

/**
 * TOKEN_BATCH:
 * TYPE | DEVICE_ID | TOKEN_COUNT | (A[j] | B[j])...
 */
#define PUFTOKEN_TOKEN_PAIR_SIZE \
    (PUFTOKEN_BLOCK_SIZE + PUFTOKEN_BLOCK_SIZE)

#define PUFTOKEN_TOKEN_BATCH_BASE_SIZE \
    (PUFTOKEN_MESSAGE_TYPE_SIZE + \
     PUFTOKEN_ID_SIZE + \
     PUFTOKEN_TOKEN_COUNT_SIZE)

#define PUFTOKEN_TOKEN_BATCH_MAX_SIZE \
    (PUFTOKEN_TOKEN_BATCH_BASE_SIZE + \
     PUFTOKEN_MAX_TOKENS_PER_SPEND * PUFTOKEN_TOKEN_PAIR_SIZE)

/**
 * SPEND_RESULT:
 * TYPE | PS_ID | STATUS
 */
#define PUFTOKEN_SPEND_RESULT_SIZE \
    (PUFTOKEN_MESSAGE_TYPE_SIZE + \
     PUFTOKEN_ID_SIZE + \
     PUFTOKEN_STATUS_SIZE)


/*
 * Big-endian serialization
 */

#define U8_TO_PUFTOKEN_ID_BE(buff) \
    (((puftoken_id_t)(*(buff)) << 8) | \
     (puftoken_id_t)(*((buff) + 1)))

#define PUFTOKEN_ID_TO_U8_BE(id, buff) \
{ \
    *((buff)) = (uint8_t)((id) >> 8); \
    *((buff) + 1) = (uint8_t)(id); \
}

#define U8_TO_TOKEN_COUNT_BE(buff) \
    (((token_count_t)(*(buff)) << 8) | \
     (token_count_t)(*((buff) + 1)))

#define TOKEN_COUNT_TO_U8_BE(count, buff) \
{ \
    *((buff)) = (uint8_t)((count) >> 8); \
    *((buff) + 1) = (uint8_t)(count); \
}

#define U8_TO_PUF_LINK_BE(buff) \
    (((uint32_t)(*((buff))) << 24) | \
     ((uint32_t)(*((buff) + 1)) << 16) | \
     ((uint32_t)(*((buff) + 2)) << 8) | \
     (uint32_t)(*((buff) + 3)))

#define PUF_LINK_TO_U8_BE(link, buff) \
{ \
    *((buff)) = (uint8_t)((link) >> 24); \
    *((buff) + 1) = (uint8_t)((link) >> 16); \
    *((buff) + 2) = (uint8_t)((link) >> 8); \
    *((buff) + 3) = (uint8_t)(link); \
}


/*
 * Compile-time checks
 */

static_assert(
    sizeof(puftoken_id_t) == 2U,
    "puftoken_id_t must occupy two bytes");

static_assert(
    sizeof(puf_link_t) == 4U,
    "puf_link_t must occupy four bytes");

static_assert(
    sizeof(token_count_t) == 2U,
    "token_count_t must occupy two bytes");

#endif // PUFTOKEN_COMMON_H