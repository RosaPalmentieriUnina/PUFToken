#ifndef PUFTOKEN_COMMON_H
#define PUFTOKEN_COMMON_H

#include <inttypes.h>
#include <stddef.h>

typedef uint16_t puftoken_id_t;         /* Identifier of a protocol actor */
typedef uint32_t puf_link_t;            /* Link of the PUF chain */
typedef uint16_t token_count_t;         /* Type used for ATS, RL, NRL and token counters */

#define MAX_ISS_TOK 100                 /* Number of tokens generated during the initialization */
#define MAX_TOK_PER_SPEND MAX_ISS_TOK   /* Maximum number of tokens transferable in a single transaction */

#define KEY_SIZE 16                     /* Lenght of Key (128 bit)*/
#define BLOCK_SIZE 16                   /* Lenght of Encrypted Block */
#define BANK_PUBLIC_KEY_SIZE 16         /* Temporary sizes used for the simulated asymmetric primitive */
#define BANK_PRIVATE_KEY_SIZE 16        /* Temporary sizes used for the simulated asymmetric primitive */
#define BANK_SIGNATURE_SIZE 16          /* Temporary sizes used for the simulated asymmetric primitive */


typedef struct
{
    uint8_t bytes[KEY_SIZE];
} puftoken_key_t;                       /* Session key RA or RB. */

typedef struct
{
    uint8_t bytes[BLOCK_SIZE];
} puftoken_block_t;                     /* Encrypted block used both for protected links and for values produced by the simulated Bank */

typedef struct
{
    uint8_t bytes[BANK_PUBLIC_KEY_SIZE];
} puftoken_bank_public_key_t;           /* Public key of the Bank */

typedef struct
{
    uint8_t bytes[BANK_PRIVATE_KEY_SIZE];
} puftoken_bank_private_key_t;          /* Private key of the Bank */

typedef struct
{
    uint8_t bytes[BANK_SIGNATURE_SIZE];

} puftoken_bank_signature_t;            /* Signature produced by the Bank using its private key */

typedef enum
{
    SPEND_REQUEST,
    SPEND_AUTH_RESULT,
    TOKEN_BATCH,
    SPEND_RESULT
} puftoken_message_t;

/* Logical protocol outcomes exchanged between the Device and the Payment System. */
typedef enum
{
    STATUS_OK,
    STATUS_INTEGRITY_FAIL,
    STATUS_INVALID_AMOUNT,
    STATUS_ACCEPT,
    STATUS_INVALID_TOKEN
} puftoken_status_t;

/* Technical return values used by functions to indicate success or failure. */
typedef enum
{
    RET_OK,
    RET_INVALID_ARGUMENT,
    RET_INVALID_STATE,
    RET_INVALID_PACKET,
    RET_BUFFER_TOO_SMALL,
    RET_CRYPTO_ERROR,
    RET_SIGNATURE_INVALID
} puftoken_ret_t;


#define MESSAGE_TYPE_SIZE sizeof(uint8_t)
#define ID_SIZE sizeof(puftoken_id_t)
#define TOKEN_COUNT_SIZE sizeof(token_count_t)
#define STATUS_SIZE sizeof(uint8_t)


/**
 * Plaintext representation of Q || RL.
 */
#define STATE_PLAINTEXT_SIZE (sizeof(puf_link_t) + sizeof(token_count_t))


/**
 * TYPE | DEVICE_ID | ATS | ENC_RA(Q || RL) | ENC_BANK(Q || RL)
 */
#define SPEND_REQUEST_SIZE (MESSAGE_TYPE_SIZE + ID_SIZE + TOKEN_COUNT_SIZE + BLOCK_SIZE + BANK_SIGNATURE_SIZE)

/**
 * TYPE | PS_ID | STATUS
 */
#define SPEND_AUTH_RESULT_BASE_SIZE (MESSAGE_TYPE_SIZE + ID_SIZE + STATUS_SIZE)

#define SPEND_AUTH_RESULT_OK_SIZE (SPEND_AUTH_RESULT_BASE_SIZE + TOKEN_COUNT_SIZE)

/**
 * TYPE | DEVICE_ID | TOKEN_COUNT | (A[j] | B[j])...
 */
#define TOKEN_PAIR_SIZE (BLOCK_SIZE + BANK_SIGNATURE_SIZE)

#define TOKEN_BATCH_BASE_SIZE (MESSAGE_TYPE_SIZE + ID_SIZE + TOKEN_COUNT_SIZE)

#define TOKEN_BATCH_MAX_SIZE (TOKEN_BATCH_BASE_SIZE + MAX_TOK_PER_SPEND * TOKEN_PAIR_SIZE)

/**
 * TYPE | PS_ID | STATUS
 */
#define SPEND_RESULT_SIZE (MESSAGE_TYPE_SIZE + ID_SIZE + STATUS_SIZE)


#define U8_TO_PUFTOKEN_ID_BE(buff) \
    (((puftoken_id_t)(*(buff)) << 8) | \
     (puftoken_id_t)(*((buff) + 1)))

#define id_tO_U8_BE(id, buff) \
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

#endif