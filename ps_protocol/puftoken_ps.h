#ifndef PUFTOKEN_PS_H
#define PUFTOKEN_PS_H

#define PS_PC_DBG 1

#if PS_PC_DBG
#include <stdio.h>
#endif

#include "ps_common.h"


typedef enum
{
    PS_WAIT_SPEND_REQUEST,  /* The Payment System is waiting for a new SPEND_REQUES from a Device */
    PS_WAIT_TOKEN_BATCH     /* The initial request has been accepted and the Payment System is waiting for TOKEN_BATCH */

} PUFToken_PS_State;


typedef struct
{
    puftoken_id_t id;                  /* Identifier of this Payment System */
    puftoken_id_t dev_id;              /* Identifier of the Device involved in the current transaction */
    PUFToken_PS_State ps_state;        /* Current state of the automaton */

    puftoken_key_t ra;                              /* Key used to process messages sent from the Device to the Payment System */
    puftoken_bank_public_key_t bank_public_key;     /* Bank public key */
    puftoken_bank_private_key_t bank_private_key;   /* Bank private key for this proof of concept*/
    
    token_count_t ats;                 /* Amount To Spend requested by the Device */
    puf_link_t q;                      /* Current Q received from the Device */
    token_count_t rl;                  /* Current Remaining Links received from the Device */
    token_count_t nrl;                 /* New Remaining Links calculated as: NRL = RL - ATS */

    uint8_t unicast_tsmt_buff[SPEND_RESULT_ACCEPT_SIZE];   /* Buffer containing the next response to send to the Device */
    uint32_t unicast_tsmt_len;         /* Number of valid bytes currently stored inside the transmission buffer */
    uint8_t unicast_is_present;        /* 0: no response available; 1: response ready to be sent */

} PaymentSystem;


/*
 * Payment System protocol functions
 */

/**
 * Initializes the Payment System structure.
 */
puftoken_ret_t puftoken_ps_setup(
    PaymentSystem* const ps,
    const puftoken_id_t ps_id,
    const puftoken_key_t* const ra,
    const puftoken_bank_public_key_t* const bank_public_key,
    const puftoken_bank_private_key_t* const bank_private_key);


/**
 * Processes SPEND_REQUEST received from the Device.
 *
 * The function verifies the certified state and ATS,
 * stores the transaction context and constructs
 * SPEND_AUTH_RESULT.
 */
puftoken_ret_t puftoken_ps_spend_request_cb(
    PaymentSystem* const ps,
    const uint8_t* const rcvd_pkt,
    const uint32_t pkt_len);


/**
 * Processes TOKEN_BATCH received from the Device.
 *
 * The function verifies every pair A[j], B[j] and constructs
 * the final SPEND_RESULT.
 */
puftoken_ret_t puftoken_ps_token_batch_cb(
    PaymentSystem* const ps,
    const uint8_t* const rcvd_pkt,
    const uint32_t pkt_len);


/**
 * Payment System automaton.
 *
 * It examines the current Payment System state and the
 * received message type, then invokes the appropriate callback.
 */
puftoken_ret_t puftoken_ps_automa(
    PaymentSystem* const ps,
    const uint8_t* const rcvd_pkt,
    const uint32_t pkt_len);

    
#endif