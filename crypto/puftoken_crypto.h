#ifndef PUFTOKEN_CRYPTO_H
#define PUFTOKEN_CRYPTO_H

#include "../puftoken_common.h"


/*
 * Generates the public/private key pair of the simulated Bank.
 *
 * The implementation is initially simulated and will later be
 * replaced by the selected asymmetric cryptographic primitive.
 */
puftoken_ret_t puftoken_bank_generate_key_pair(
    puftoken_bank_public_key_t* const public_key,
    puftoken_bank_private_key_t* const private_key);


/*
 * Produces a Bank signature over an arbitrary byte sequence.
 *
 * Only the Bank uses this operation.
 */
puftoken_ret_t puftoken_bank_sign(
    const puftoken_bank_private_key_t* const private_key,
    const uint8_t* const data,
    const uint32_t data_len,
    puftoken_bank_signature_t* const signature);


/*
 * Verifies a Bank signature over an arbitrary byte sequence.
 *
 * The Payment System uses this operation during spending.
 */
puftoken_ret_t puftoken_bank_verify(
    const puftoken_bank_public_key_t* const public_key,
    const uint8_t* const data,
    const uint32_t data_len,
    const puftoken_bank_signature_t* const signature);

#endif