#include "puftoken_crypto.h"

#include <string.h>

#include "puftoken_common.h"

/*
 * Weak functions can be replaced by a platform-specific
 * implementation when the project is ported to the target board.
 */
#if defined(__GNUC__) || defined(__clang__)
#define PUFTOKEN_WEAK __attribute__((weak))
#else
#define PUFTOKEN_WEAK
#endif

/*
 * Parameters used only by the simulated key-generation function.
 */
#define SIMULATED_PRIVATE_KEY_BASE 0xA0U
#define SIMULATED_PUBLIC_KEY_MASK  0x5AU

static void puftoken_simulated_digest(
    const uint8_t* const data,
    const uint32_t data_len,
    uint8_t digest[BANK_SIGNATURE_SIZE])
{
    memset( digest, 0, BANK_SIGNATURE_SIZE);

    for (uint32_t i = 0U; i < data_len; ++i) {

        const uint32_t digest_index = i % BANK_SIGNATURE_SIZE;
        digest[digest_index] = (uint8_t)( digest[digest_index] ^ data[i] ^ (uint8_t)(i + 1U));
    }
}


PUFTOKEN_WEAK puftoken_ret_t puftoken_bank_generate_key_pair(
    puftoken_bank_public_key_t* const public_key,
    puftoken_bank_private_key_t* const private_key)
{
    if ((public_key == NULL) || (private_key == NULL)) {
        return RET_INVALID_ARGUMENT;
    }

    memset( public_key, 0, sizeof(*public_key));
    memset( private_key, 0, sizeof(*private_key));

    /*
     * Generate a deterministic simulated private key.
     *
     * With a size of 16 bytes, the result is:
     *
     * A0 A1 A2 A3 A4 A5 A6 A7
     * A8 A9 AA AB AC AD AE AF
     */
    for (uint32_t i = 0U; i < BANK_PRIVATE_KEY_SIZE; ++i) {
        private_key->bytes[i] = (uint8_t)(SIMULATED_PRIVATE_KEY_BASE + i);
    }

    for (uint32_t i = 0U; i < BANK_PUBLIC_KEY_SIZE; ++i) {
        public_key->bytes[i] = (uint8_t)( private_key->bytes[i] ^ SIMULATED_PUBLIC_KEY_MASK);
    }

    return RET_OK;
}

PUFTOKEN_WEAK puftoken_ret_t puftoken_bank_sign(
    const puftoken_bank_private_key_t* const private_key,
    const uint8_t* const data,
    const uint32_t data_len,
    puftoken_bank_signature_t* const signature)
{
    if ((private_key == NULL) || (data == NULL) || (signature == NULL) || (data_len == 0U)) {
        return RET_INVALID_ARGUMENT;
    }

    uint8_t digest[BANK_SIGNATURE_SIZE] = {0U};

    puftoken_simulated_digest(data, data_len, digest);

    memset(signature, 0, sizeof(*signature));

    for (uint32_t i = 0U; i < BANK_SIGNATURE_SIZE; ++i) {
        signature->bytes[i] = (uint8_t)(digest[i] ^ private_key->bytes[i % BANK_PRIVATE_KEY_SIZE]);
    }

    return RET_OK;
}

PUFTOKEN_WEAK puftoken_ret_t puftoken_bank_verify(
    const puftoken_bank_public_key_t* const public_key,
    const uint8_t* const data,
    const uint32_t data_len,
    const puftoken_bank_signature_t* const signature)
{
    if ((public_key == NULL) || (data == NULL) || (signature == NULL) || (data_len == 0U)) {
        return RET_INVALID_ARGUMENT;
    }

    uint8_t digest[BANK_SIGNATURE_SIZE] = {0U};

    puftoken_simulated_digest(data, data_len, digest);

    uint8_t difference = 0U;

    for (uint32_t i = 0U; i < BANK_SIGNATURE_SIZE; ++i) {

        const uint8_t recovered_digest_byte = (uint8_t)(signature->bytes[i] ^ public_key->bytes[i % BANK_PUBLIC_KEY_SIZE] ^ SIMULATED_PUBLIC_KEY_MASK );

        difference = (uint8_t)(difference | (digest[i] ^ recovered_digest_byte));
    }

    if (difference != 0U) {
        return RET_SIGNATURE_INVALID;
    }

    return RET_OK;
}

PUFTOKEN_WEAK puftoken_ret_t puftoken_symmetric_encrypt(
    const puftoken_key_t* const key,
    const puftoken_block_t* const plaintext,
    puftoken_block_t* const ciphertext)
{
    if ((key == NULL) ||
        (plaintext == NULL) ||
        (ciphertext == NULL))
    {
        return RET_INVALID_ARGUMENT;
    }

    for (uint32_t i = 0U; i < BLOCK_SIZE; ++i) {
        ciphertext->bytes[i] =
            (uint8_t)(plaintext->bytes[i] ^ key->bytes[i]);
    }

    return RET_OK;
}

PUFTOKEN_WEAK puftoken_ret_t puftoken_symmetric_decrypt(
    const puftoken_key_t* const key,
    const puftoken_block_t* const ciphertext,
    puftoken_block_t* const plaintext)
{
    if ((key == NULL) ||
        (ciphertext == NULL) ||
        (plaintext == NULL))
    {
        return RET_INVALID_ARGUMENT;
    }

    for (uint32_t i = 0U; i < BLOCK_SIZE; ++i) {
        plaintext->bytes[i] =
            (uint8_t)(ciphertext->bytes[i] ^ key->bytes[i]);
    }

    return RET_OK;
}