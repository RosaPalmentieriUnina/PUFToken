#include <stdio.h>
#include <inttypes.h>
#include <string.h>

#include "puftoken_common.h"
#include "puftoken_dev.h"
#include "puftoken_ps.h"
#include "puftoken_crypto.h"
#include "puftoken_puf.h"
#include "puftoken_setup.h"

int main()
{

    printf("\n---------------------- DEVICE TEST ----------------------\n");

    Device dev = {};

    puftoken_key_t ra = {};

    puftoken_bank_signature_t certified_state = {};

    const token_count_t test_token_count = 10U;

    puftoken_bank_signature_t bank_tokens[10] = {};

    /*
    * Assign recognizable test values.
    */
    ra.bytes[0] = 0xAAU;

    certified_state.bytes[0] = 0xCCU;
    bank_tokens[0].bytes[0] = 0xDDU;

    const puftoken_ret_t setup_result =
        puftoken_dev_setup(
            &dev,
            1U,
            2U,
            &ra,
            0x11223344U,
            test_token_count,
            test_token_count,
            &certified_state,
            bank_tokens);

    if (setup_result != RET_OK)
    {
        printf("Device setup failed.\n");
        return 1;
    }

    printf("Device setup completed correctly.\n");

    printf(
        "Device ID: %" PRIu16 "\n",
        dev.id);

    printf(
        "Payment System ID: %" PRIu16 "\n",
        dev.ps_id);

    printf(
        "Device Q: 0x%08" PRIX32 "\n",
        dev.q);

    printf(
        "Device RL: %" PRIu16 "\n",
        dev.rl);

    printf(
        "Issued tokens: %" PRIu16 "\n",
        dev.iss_tok_count);

    printf(
        "RA first byte: 0x%02" PRIX8 "\n",
        dev.ra.bytes[0]);

    printf(
        "Certified state first byte: 0x%02" PRIX8 "\n",
        dev.certified_state.bytes[0]);

    printf(
        "First Bank token first byte: 0x%02" PRIX8 "\n",
        dev.bank_tokens[0].bytes[0]);



        
    printf("\n---------------------- PAYMENT SYSTEM TEST ----------------------\n");

    PaymentSystem ps = {};

    puftoken_bank_public_key_t bank_public_key = {};
    puftoken_bank_private_key_t bank_private_key = {};

    const puftoken_ret_t key_pair_result =
        puftoken_bank_generate_key_pair(
            &bank_public_key,
            &bank_private_key);

    if (key_pair_result != RET_OK)
    {
        printf("Bank key-pair generation failed.\n");
        return 1;
    }

    if ((bank_private_key.bytes[0] != 0xA0U) ||
        (bank_public_key.bytes[0] != 0xFAU))
    {
        printf("Bank key-pair generation test failed.\n");
        return 1;
    }

    printf("Bank key pair generated correctly.\n");

    printf(
        "Bank private key first byte: 0x%02" PRIX8 "\n",
        bank_private_key.bytes[0]);

    printf(
        "Bank public key first byte:  0x%02" PRIX8 "\n",
    bank_public_key.bytes[0]);

    const puftoken_ret_t ps_setup_result =
        puftoken_ps_setup(
            &ps,
            2U,
            &ra,
            &bank_public_key,
            &bank_private_key);

    if (memcmp(&ps.bank_public_key, &bank_public_key, sizeof(ps.bank_public_key)) != 0) {
        printf("Bank public key was not copied correctly.\n");
        return 1;
    }

    if (memcmp(&ps.bank_private_key, &bank_private_key, sizeof(ps.bank_private_key)) != 0) {
        printf("Bank private key was not copied correctly.\n");
        return 1;
    }

    printf("Bank private key first byte: 0x%02" PRIX8 "\n", ps.bank_private_key.bytes[0]);

    if (ps_setup_result != RET_OK) {
        printf("Payment System setup failed.\n");
        return 1;
    }

    /*
    * Verify the most important initialized fields.
    */
    if ((ps.id != 2U) ||
        (ps.ps_state != PS_WAIT_SPEND_REQUEST) ||
        (ps.ra.bytes[0] != 0xAAU) ||
        (ps.bank_public_key.bytes[0] != 0xFAU) ||
        (ps.unicast_tsmt_len != 0U) ||
        (ps.unicast_is_present != 0U))
    {
        printf("Payment System setup test failed.\n");
        return 1;
    }

    printf("Payment System setup completed correctly.\n");

    printf(
        "Payment System ID: %" PRIu16 "\n",
        ps.id);

    printf(
        "Payment System state: %u\n",
        (unsigned int)ps.ps_state);

    printf(
        "RA first byte: 0x%02" PRIX8 "\n",
        ps.ra.bytes[0]);

    printf(
        "Bank public key first byte: 0x%02" PRIX8 "\n",
        ps.bank_public_key.bytes[0]);




    printf("\n---------------------- CRYPTO TEST ----------------------\n");

    /*
    * Build the serialized representation of: Q || RL
    */
    uint8_t state_plaintext[STATE_PLAINTEXT_SIZE] = {0U};

    const puf_link_t test_q = 0x11223344U;
    const token_count_t test_rl = 10U;

    PUF_LINK_TO_U8_BE(
        test_q,
        state_plaintext);

    TOKEN_COUNT_TO_U8_BE(
        test_rl,
        &state_plaintext[sizeof(puf_link_t)]);


    /*
    * Sign the state using the Bank private key.
    */
    puftoken_bank_signature_t state_signature = {};

    const puftoken_ret_t sign_result =
        puftoken_bank_sign(
            &bank_private_key,
            state_plaintext,
            STATE_PLAINTEXT_SIZE,
            &state_signature);

    if (sign_result != RET_OK)
    {
        printf("Bank signature generation failed.\n");
        return 1;
    }

    printf("Bank signature generated correctly.\n");

    printf(
        "Signature first byte: 0x%02" PRIX8 "\n",
        state_signature.bytes[0]);

    puftoken_bank_signature_t second_signature = {};

    if (puftoken_bank_sign(
            &bank_private_key,
            state_plaintext,
            STATE_PLAINTEXT_SIZE,
            &second_signature) != RET_OK)
    {
        printf("Second Bank signature generation failed.\n");
        return 1;
    }

    if (memcmp(
            &state_signature,
            &second_signature,
            sizeof(state_signature)) != 0)
    {
        printf("Simulated signature is not deterministic.\n");
        return 1;
    }

    printf("Deterministic signature test passed.\n");

    const puftoken_ret_t verify_result =
        puftoken_bank_verify(
            &bank_public_key,
            state_plaintext,
            STATE_PLAINTEXT_SIZE,
            &state_signature);

    if (verify_result != RET_OK)
    {
        printf("Valid Bank signature was rejected.\n");
        return 1;
    }

    printf("Valid Bank signature accepted correctly.\n");


    uint8_t modified_state[STATE_PLAINTEXT_SIZE] = {0U};

    memcpy(
        modified_state,
        state_plaintext,
        STATE_PLAINTEXT_SIZE);

    /*
    * Alter one byte of Q.
    */
    modified_state[0] ^= 0x01U;

    const puftoken_ret_t modified_data_result =
        puftoken_bank_verify(
            &bank_public_key,
            modified_state,
            STATE_PLAINTEXT_SIZE,
            &state_signature);

    if (modified_data_result != RET_SIGNATURE_INVALID)
    {
        printf("Modified data signature test failed.\n");
        return 1;
    }

    printf("Modified data rejected correctly.\n");

    puftoken_bank_signature_t modified_signature =
    state_signature;

    /*
    * Alter one byte of the signature.
    */
    modified_signature.bytes[0] ^= 0x01U;

    const puftoken_ret_t modified_signature_result =
        puftoken_bank_verify(
            &bank_public_key,
            state_plaintext,
            STATE_PLAINTEXT_SIZE,
            &modified_signature);

    if (modified_signature_result != RET_SIGNATURE_INVALID)
    {
        printf("Modified signature test failed.\n");
        return 1;
    }

    printf("Modified signature rejected correctly.\n");

    if (puftoken_bank_verify(
            NULL,
            state_plaintext,
            STATE_PLAINTEXT_SIZE,
            &state_signature) != RET_INVALID_ARGUMENT)
    {
        printf("NULL public-key verification test failed.\n");
        return 1;
    }


    printf(
    "\n---------------------- SYMMETRIC CRYPTO TEST ----------------------\n");

    puftoken_key_t symmetric_test_key = {};

    for (uint32_t i = 0U; i < KEY_SIZE; ++i) {
        symmetric_test_key.bytes[i] = (uint8_t)(0x10U + i);
    }

    puftoken_block_t plaintext = {};
    puftoken_block_t ciphertext = {};
    puftoken_block_t recovered_plaintext = {};

    for (uint32_t i = 0U; i < BLOCK_SIZE; ++i) {
        plaintext.bytes[i] = (uint8_t)i;
    }

    puftoken_ret_t symmetric_result =
    puftoken_symmetric_encrypt(
        &symmetric_test_key,
        &plaintext,
        &ciphertext);

    if (symmetric_result != RET_OK) {
        printf("Symmetric encryption failed.\n");
        return 1;
    }

    if (memcmp(&plaintext, &ciphertext, sizeof(plaintext)) == 0) {
        printf("Symmetric encryption did not modify the plaintext.\n");
        return 1;
    }

    printf("Symmetric encryption completed correctly.\n");

    symmetric_result =
        puftoken_symmetric_decrypt(
            &symmetric_test_key,
            &ciphertext,
            &recovered_plaintext);

    if (symmetric_result != RET_OK) {
        printf("Symmetric decryption failed.\n");
        return 1;
    }

    if (memcmp(&plaintext, &recovered_plaintext, sizeof(plaintext)) != 0) {
        printf("Recovered plaintext does not match the original plaintext.\n");
        return 1;
    }

    printf("Symmetric decryption completed correctly.\n");
    printf("Recovered plaintext matches the original plaintext.\n");

    if (puftoken_symmetric_encrypt(NULL, &plaintext, &ciphertext) != RET_INVALID_ARGUMENT){
        printf("Symmetric invalid-argument test failed.\n");
        return 1;
    }

    printf("Symmetric invalid-argument test completed correctly.\n");

    printf("\n---------------------- PUF CHAIN TEST ----------------------\n");

    const puf_link_t initial_link = 0x11223344U;

    puf_link_t first_link = 0U;
    puf_link_t second_link = 0U;
    puf_link_t third_link = 0U;

    if (next_puf_link(
            initial_link,
            &first_link) != RET_OK)
    {
        printf("First simulated PUF evaluation failed.\n");
        return 1;
    }

    if (next_puf_link(
            first_link,
            &second_link) != RET_OK)
    {
        printf("Second simulated PUF evaluation failed.\n");
        return 1;
    }

    if (next_puf_link(
            second_link,
            &third_link) != RET_OK)
    {
        printf("Third simulated PUF evaluation failed.\n");
        return 1;
    }

    printf("Simulated PUF chain generated correctly.\n");

    printf(
        "Initial link: 0x%08" PRIX32 "\n",
        initial_link);

    printf(
        "First link:   0x%08" PRIX32 "\n",
        first_link);

    printf(
        "Second link:  0x%08" PRIX32 "\n",
        second_link);

    printf(
        "Third link:   0x%08" PRIX32 "\n",
        third_link);

    /*
    * Verify the expected chain values.
    */
    if ((first_link != 0x96C3F069U) ||
        (second_link != 0x1EE1B51EU) ||
        (third_link != 0x86877A87U))
    {
        printf("Unexpected simulated PUF chain values.\n");
        return 1;
    }

    printf("Simulated PUF expected-values test passed.\n");

    /*
    * Verify that a NULL output pointer is rejected.
    */
    if (next_puf_link(
            initial_link,
            NULL) != RET_INVALID_ARGUMENT)
    {
        printf("NULL next-link test failed.\n");
        return 1;
    }

    printf("NULL next-link test passed.\n");



    printf("\n---------------------- SETUP TEST ----------------------\n");

    Device setup_dev = {};
    PaymentSystem setup_ps = {};

    const puf_link_t setup_initial_q =
        0x11223344U;

    const token_count_t setup_token_count =
        10U;

    const puftoken_ret_t complete_setup_result =
        puftoken_setup(
            &setup_dev,
            &setup_ps,
            1U,
            2U,
            setup_initial_q,
            setup_token_count);

    if (complete_setup_result != RET_OK)
    {
        printf("Complete PUFToken setup failed.\n");
        return 1;
    }

    if ((setup_dev.id != 1U) ||
        (setup_dev.ps_id != 2U) ||
        (setup_dev.q != setup_initial_q) ||
        (setup_dev.rl != setup_token_count) ||
        (setup_dev.iss_tok_count != setup_token_count) ||
        (setup_dev.dev_state != DEV_READY))
    {
        printf("Complete Device setup test failed.\n");
        return 1;
    }

    if ((setup_ps.id != 2U) ||
        (setup_ps.ps_state != PS_WAIT_SPEND_REQUEST)) {
        printf("Complete Payment System setup test failed.\n");
        return 1;
    }

    if (setup_ps.bank_private_key.bytes[0] != 0xA0U) {
        printf("Bank private key was not installed in the Payment System.\n");
        return 1;
    }

    printf("Payment System Bank private key first byte: 0x%02" PRIX8 "\n", setup_ps.bank_private_key.bytes[0]);

    if (memcmp(
        &setup_dev.ra,
        &setup_ps.ra,
        sizeof(setup_dev.ra)) != 0)
    {
        printf("RA mismatch after complete setup.\n");
        return 1;
    }

    uint8_t setup_state[STATE_PLAINTEXT_SIZE] = {0U};

    PUF_LINK_TO_U8_BE(
        setup_dev.q,
        setup_state);

    TOKEN_COUNT_TO_U8_BE(
        setup_dev.rl,
        &setup_state[sizeof(puf_link_t)]);

    if (puftoken_bank_verify(
        &setup_ps.bank_public_key,
        setup_state,
        STATE_PLAINTEXT_SIZE,
        &setup_dev.certified_state) != RET_OK)
    {
        printf("Initial certified-state verification failed.\n");
        return 1;
    }

    printf("Initial certified state verified correctly.\n");

    puf_link_t first_setup_link = 0U;

    if (next_puf_link(
            setup_dev.q,
            &first_setup_link) != RET_OK)
    {
        printf("First setup PUF-link generation failed.\n");
        return 1;
    }

    uint8_t first_setup_link_data[sizeof(puf_link_t)] = {0U};

    PUF_LINK_TO_U8_BE(
        first_setup_link,
        first_setup_link_data);

    if (puftoken_bank_verify(
        &setup_ps.bank_public_key,
        first_setup_link_data,
        sizeof(first_setup_link_data),
        &setup_dev.bank_tokens[0]) != RET_OK)
    {
        printf("First setup token verification failed.\n");
        return 1;
    }

    printf("First setup token verified correctly.\n");
    
    puftoken_dev_cleanup(&dev);
    puftoken_dev_cleanup(&setup_dev);

    return 0;
}