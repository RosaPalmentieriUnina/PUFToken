#include "puftoken_setup.h"

#include "../crypto/puftoken_crypto.h"
#include "../puf/puftoken_puf.h"

#include <string.h>


/*
 * Initial values used only to generate deterministic
 * simulated session keys.
 */
#define SIMULATED_RA_BASE 0x10U
#define SIMULATED_RB_BASE 0x80U


/*
 * Generates deterministic simulated session keys.
 */
static void generate_simulated_session_keys(
    puftoken_key_t* const ra,
    puftoken_key_t* const rb)
{
    for (uint32_t i = 0U; i < KEY_SIZE; ++i) {
        ra->bytes[i] = (uint8_t)(SIMULATED_RA_BASE + i);
        rb->bytes[i] = (uint8_t)(SIMULATED_RB_BASE + i);
    }
}


puftoken_ret_t puftoken_setup(
    Device* const dev,
    PaymentSystem* const ps,
    const puftoken_id_t dev_id,
    const puftoken_id_t ps_id,
    const puf_link_t initial_q,
    const token_count_t issued_token_count)
{
    if ((dev == NULL) || (ps == NULL)) {
        return RET_INVALID_ARGUMENT;
    }

    /*
     * At least one token must be issued and the Device
     * cannot store more than MAX_ISS_TOK tokens.
     */
    if ((issued_token_count == 0U) || (issued_token_count > MAX_ISS_TOK)) {
        return RET_INVALID_ARGUMENT;
    }

    memset(dev, 0, sizeof(*dev));
    memset(ps, 0, sizeof(*ps));

    puftoken_key_t ra = {};
    puftoken_key_t rb = {};

    puftoken_bank_public_key_t bank_public_key = {};
    puftoken_bank_private_key_t bank_private_key = {};

    puftoken_bank_signature_t certified_state = {};

    /*
     * The complete token-signature array is static so that
     * it is not allocated on the function stack.
     *
     * It is cleared at every setup execution.
     */
    static puftoken_bank_signature_t bank_tokens[MAX_ISS_TOK];

    memset(bank_tokens, 0, sizeof(bank_tokens));

    generate_simulated_session_keys(&ra, &rb);

    puftoken_ret_t result = puftoken_bank_generate_key_pair(&bank_public_key, &bank_private_key);

    if (result != RET_OK) {
        return result;
    }

    const token_count_t initial_rl = issued_token_count;

    /*
     * State: Q || RL
     */
    uint8_t state_plaintext[STATE_PLAINTEXT_SIZE] = {0U};

    PUF_LINK_TO_U8_BE(initial_q, state_plaintext);

    TOKEN_COUNT_TO_U8_BE(initial_rl, &state_plaintext[sizeof(puf_link_t)]);

    /*
     * The Bank certifies the initial state using its private key.
     */
    result = puftoken_bank_sign(&bank_private_key, state_plaintext, STATE_PLAINTEXT_SIZE, &certified_state);

    if (result != RET_OK) {
        memset(&bank_private_key, 0, sizeof(bank_private_key));

        return result;
    }

    puf_link_t current_link = initial_q;

    for (token_count_t i = 0U; i < issued_token_count; ++i) {
        puf_link_t generated_link = 0U;

        result = next_puf_link(current_link, &generated_link);

        if (result != RET_OK) {
            memset(&bank_private_key, 0, sizeof(bank_private_key));

            return result;
        }

        uint8_t link_plaintext[sizeof(puf_link_t)] = {0U};

        PUF_LINK_TO_U8_BE(generated_link, link_plaintext);

        /*
         * Store the Bank signature associated with this link.
         */
        result = puftoken_bank_sign(&bank_private_key, link_plaintext, sizeof(link_plaintext), &bank_tokens[i]);

        if (result != RET_OK) {
            memset(&bank_private_key, 0, sizeof(bank_private_key));

            return result;
        }

        /*
         * Advance along the simulated PUF chain.
         */
        current_link = generated_link;
    }

    result =
        puftoken_dev_setup(
            dev,
            dev_id,
            ps_id,
            &ra,
            &rb,
            initial_q,
            initial_rl,
            issued_token_count,
            &certified_state,
            bank_tokens);

    if (result != RET_OK) {
        memset(&bank_private_key, 0, sizeof(bank_private_key));
        memset(dev, 0, sizeof(*dev));

        return result;
    }

    result =
        puftoken_ps_setup(
            ps,
            ps_id,
            &ra,
            &rb,
            &bank_public_key);

    if (result != RET_OK)
    {
        memset(&bank_private_key, 0, sizeof(bank_private_key));
        memset(dev, 0, sizeof(*dev));
        memset(ps, 0, sizeof(*ps));

        return result;
    }

    memset(&bank_private_key, 0, sizeof(bank_private_key));

    return RET_OK;
}