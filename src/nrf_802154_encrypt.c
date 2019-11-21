/* Copyright (c) 2016-2019 Nordic Semiconductor ASA
 * Copyright (c) 2015 Nordic Semiconductor ASA and Luxoft Global Operations Gmbh.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   1. Redistributions of source code must retain the above copyright notice, this
 *      list of conditions and the following disclaimer.
 *
 *   2. Redistributions in binary form must reproduce the above copyright notice,
 *      this list of conditions and the following disclaimer in the documentation
 *      and/or other materials provided with the distribution.
 *
 *   3. Neither the name of Nordic Semiconductor ASA nor the names of its
 *      contributors may be used to endorse or promote products derived from
 *      this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/**
 * @file
 *  This file implements AES-CCM* encryption for the nRF 802.15.4 radio driver.
 *  Based on IEEE Standard for Low-Rate Wireless Networks  - IEEE Std 802.15.4-2015
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "nrf_802154_encrypt.h"
#include "nrf_ecb.h"

/**
 * @brief Mode of operation Annex B3.2e
 */
enum mic_size_t
{
    MIC_NONE = 0,
    MIC32    = 4,
    MIC64    = 8,
    MIC128   = 16
};

/**
 * @brief Steps of AES-CCM* algorithm.
 */
typedef enum
{
    ADD_AUTH_DATA_AUTH,
    PLAIN_TEXT_AUTH,
    PLAIN_TEXT_ENCRYPT,
    CALCULATE_ENCRYPTED_TAG
} ccm_steps_t;

/**
 * @brief Actual state of perfomed AES-CCM* algorithm.
 */
typedef struct
{
    ccm_steps_t transformation;                                                        // Actual step of transformation
    uint8_t     iteration;                                                             // Iteration of actual step of transformation
} ccm_state_t;

#define MIN(a, b)  ((a) < (b) ? (a) : (b))                                             ///< Leaves the minimum of the two arguments

#define ECBKEY     (nrf_ecb_data_pointer_get(NRF_ECB))                                 ///< Macro AES Key Address
#define CLEARTEXT  (nrf_ecb_data_pointer_get(NRF_ECB) + 16)                            ///< Macro AES ClearText Address
#define CYPHERTEXT (nrf_ecb_data_pointer_get(NRF_ECB) + 32)                            ///< Macro AES CipherText Address

static nrf_802154_encrypt_aes_ccm_frame_t m_aes_ccm_frame;                             ///< AES CCM Frame
static uint8_t                            m_auth_key[NRF_802154_ENCRYPT_BLOCK_SIZE];   ///< Stored AES Key
static uint8_t                            m_auth_nonce[NRF_802154_ENCRYPT_NONCE_SIZE]; ///< Stored AES-CCM* Nonce
static uint8_t                            m_x[NRF_802154_ENCRYPT_BLOCK_SIZE];          ///< CBC-MAC value - Annex B4.1.2 d)
static uint8_t                            m_b[NRF_802154_ENCRYPT_BLOCK_SIZE];          ///< B[i] octet for Authorization Transformatino - Annex B4.1.2 b)
static uint8_t                            m_m[NRF_802154_ENCRYPT_BLOCK_SIZE];          ///< M[i] octet as parsed plaintext blocks - Annex B4.1.3 c)
static uint8_t                            m_a[NRF_802154_ENCRYPT_BLOCK_SIZE];          ///< A[i] octet for Encryption Transformation - Annex B4.1.3 b)
static ccm_state_t                        m_state;                                     ///< State of AES-CCM* transformation
static uint8_t                            m_auth_tag[MIC128];                          ///< Authorization Tag

static const uint8_t m_mic_size[] = {MIC_NONE, MIC32, MIC64, MIC128};                  ///< Security level - 802.15.4-2015 Standard Table 9.6

/**
 * @brief Calculates XOR of two blocks of data
 *
 * param[inout] p_first  First block of data
 * param[in]    p_second Second block of data
 * param[in]    len      Length of blocks
 */
static void two_blocks_xor(uint8_t * p_first, const uint8_t * p_second, uint8_t len)
{
    for (uint8_t i = 0; i < len; i++)
    {
        p_first[i] ^= p_second[i];
    }
}

/**
 * @brief   Forms 16-octet Ai field
 * IEEE std 802.15.4-2015, B.4.1.3 Encryption transformation
 *
 * @param[in]  p_frame pointer to AES CCM frame structure
 * @param[in]  iter    counter of actual iteration
 * @param[out] p_a     pointer to memory for Ai
 */
static void ai_format(const nrf_802154_encrypt_aes_ccm_frame_t * p_frame,
                      uint16_t                                   iter,
                      uint8_t                                  * p_a)
{
    uint8_t enc_flags = NRF_802154_ENCRYPT_L_VALUE - 1;

    p_a[NRF_802154_ENCRYPT_AI_FIELD_FLAG_OCTET] = enc_flags;
    memcpy(&p_a[NRF_802154_ENCRYPT_AI_FIELD_NONCE_OCTET],
           p_frame->nonce,
           NRF_802154_ENCRYPT_NONCE_SIZE);
    p_a[NRF_802154_ENCRYPT_BLOCK_SIZE - 1] = iter;
    p_a[NRF_802154_ENCRYPT_BLOCK_SIZE - 2] = iter >> 8;
}

/**
 * @brief   Forms 16-octet B0 field
 * IEEE std 802.15.4-2015, B.4.1.2b Encryption transformation
 *
 * @param[in]  p_frame pointer to AES CCM frame structure
 * @param[in]  flags   flags for injection to B0 field
 * @param[out] p_b     pointer to memory for B0
 */
static void b0_format(const nrf_802154_encrypt_aes_ccm_frame_t * p_frame,
                      const uint8_t                              flags,
                      uint8_t                                  * p_b)
{
    p_b[NRF_802154_ENCRYPT_B0_FIELD_FLAG_OCTET] = flags;
    memcpy(&p_b[NRF_802154_ENCRYPT_B0_FIELD_NONCE_OCTET],
           p_frame->nonce,
           NRF_802154_ENCRYPT_NONCE_SIZE);
    p_b[NRF_802154_ENCRYPT_BLOCK_SIZE - 1] = (p_frame->plain_text_data_len & 0xFF);
    p_b[NRF_802154_ENCRYPT_BLOCK_SIZE - 2] = (p_frame->plain_text_data_len & 0xFF00) >> 8;
}

/**
 * @brief   Forms authentication flag
 * IEEE std 802.15.4-2015, B.4.1.2 Authentication transformation
 *
 * @param[in] p_frame pointer to AES CCM frame structure
 *
 * @return Formatted authorization flags
 */
static uint8_t auth_flags_format(const nrf_802154_encrypt_aes_ccm_frame_t * p_frame)
{
    uint8_t auth_flags = 0;
    uint8_t m;

    auth_flags |= (p_frame->auth_data_len == 0) ? 0 : NRF_802154_ENCRYPT_ADATA_AUTH_FLAG;

    m           = m_mic_size[p_frame->mic_level];
    m           = (m > 0) ? (m - 2) >> 1 : 0;
    auth_flags |= (m << NRF_802154_ENCRYPT_M_BITS_AUTH_FLAG);

    auth_flags |= NRF_802154_ENCRYPT_L_VALUE - 1; // l value

    return auth_flags;
}

/**
 * @brief   Forms additional authentication data from octet string a by 16-octet chunks
 * IEEE std 802.15.4-2015, B.4.1.1 Input transformation
 *
 * @param[in]  p_frame pointer to AES CCM frame structure
 * @param[in]  iter    number of chunk
 * @param[out] p_b     pointer to memory for Bi
 *
 * @retval true  Chunk was formated
 * @retval false Otherwise
 */
static bool add_auth_data_get(const nrf_802154_encrypt_aes_ccm_frame_t * p_frame,
                              uint8_t                                    iter,
                              uint8_t                                  * p_b)
{
    uint8_t offset = 0;
    uint8_t len;

    if (p_frame->auth_data_len == 0)
    {
        return false;
    }

    memset(p_b, 0, NRF_802154_ENCRYPT_BLOCK_SIZE);

    if (iter == 0)
    {
        len = MIN(p_frame->auth_data_len, NRF_802154_ENCRYPT_BLOCK_SIZE - sizeof(uint16_t));
        p_b[NRF_802154_ENCRYPT_AUTH_DATA_LENGTH_OCTET]     = (p_frame->auth_data_len & 0xFF00) >> 8;
        p_b[NRF_802154_ENCRYPT_AUTH_DATA_LENGTH_OCTET + 1] = (p_frame->auth_data_len & 0xFF);
        memcpy(&p_b[NRF_802154_ENCRYPT_AUTH_DATA_OCTET], p_frame->auth_data, len);
        return true;
    }

    offset += NRF_802154_ENCRYPT_BLOCK_SIZE - sizeof(uint16_t);
    offset += NRF_802154_ENCRYPT_BLOCK_SIZE * (iter - 1);
    if (offset >= p_frame->auth_data_len)
    {
        return false;
    }

    len = MIN(p_frame->auth_data_len - offset, NRF_802154_ENCRYPT_BLOCK_SIZE);
    memcpy(p_b, p_frame->auth_data + offset, len);
    return true;
}

/**
 * @brief   Forms plain/cipher text data from octet string m/c by 16-octet chunks
 * IEEE std 802.15.4-2015, B.4.1.1 Input transformation
 *
 * @param[in]  p_frame pointer to AES CCM frame structure
 * @param[in]  iter    number of chunk
 * @param[out] p_b     pointer to memory for Bi
 *
 * @retval true  Chunk was formated
 * @retval false Otherwise
 */
static bool plain_text_data_get(const nrf_802154_encrypt_aes_ccm_frame_t * p_frame,
                                uint8_t                                    iter,
                                uint8_t                                  * p_b)
{
    uint8_t offset = 0;
    uint8_t len;

    if (p_frame->plain_text_data_len == 0)
    {
        return false;
    }

    memset(p_b, 0, NRF_802154_ENCRYPT_BLOCK_SIZE);

    offset += NRF_802154_ENCRYPT_BLOCK_SIZE * iter;
    if (offset >= p_frame->plain_text_data_len)
    {
        return false;
    }

    len = MIN(p_frame->plain_text_data_len - offset, NRF_802154_ENCRYPT_BLOCK_SIZE);
    memcpy(p_b, p_frame->plain_text_data + offset, len);

    return true;
}

/**
 * @brief Block of Authorization Transformation iteration
 */
static inline void process_ecb_auth_iteration(void)
{
    m_state.iteration++;
    two_blocks_xor((uint8_t *)CYPHERTEXT, m_b, NRF_802154_ENCRYPT_BLOCK_SIZE);
    memcpy(CLEARTEXT, CYPHERTEXT, NRF_802154_ENCRYPT_BLOCK_SIZE);
    NRF_ECB->TASKS_STARTECB = 1;
}

/**
 * @brief Block of Encryption Transformation iteration
 */
static inline void process_ecb_encrypt_iteration(void)
{
    ai_format(&m_aes_ccm_frame, m_state.iteration, m_a);
    memcpy(CLEARTEXT, m_a, NRF_802154_ENCRYPT_BLOCK_SIZE);
    NRF_ECB->TASKS_STARTECB = 1;
}

/**
 * @brief helper function for plain text encryption in ECB IRQ
 */
static void perform_plain_text_encryption(void)
{
    memcpy(m_auth_tag, CYPHERTEXT, m_mic_size[m_aes_ccm_frame.mic_level]);

    m_state.iteration      = 0;
    m_state.transformation = PLAIN_TEXT_ENCRYPT;

    if (plain_text_data_get(&m_aes_ccm_frame, m_state.iteration, m_m))
    {
        m_state.iteration++;
        process_ecb_encrypt_iteration();
    }
    else
    {
        if (m_mic_size[m_aes_ccm_frame.mic_level] != 0)
        {
            process_ecb_encrypt_iteration();
            m_state.transformation = CALCULATE_ENCRYPTED_TAG;
        }
    }
}

/**
 * @brief helper function for plain text auth in ECB IRQ
 */
static void perform_plain_text_authorization(void)
{
    if (plain_text_data_get(&m_aes_ccm_frame, m_state.iteration, m_b))
    {
        process_ecb_auth_iteration();
    }
    else
    {
        perform_plain_text_encryption();
    }
}

/**
 * @brief Handler to ECB Interrupt Routine
 *  Performs AES-CCM* calculation in pipeline
 */
void ECB_IRQHandler(void)
{
    uint8_t len    = 0;
    uint8_t offset = 0;

    if (NRF_ECB->EVENTS_ENDECB != 0)
    {
        NRF_ECB->EVENTS_ENDECB = 0;

        switch (m_state.transformation)
        {
            case ADD_AUTH_DATA_AUTH:
                if (add_auth_data_get(&m_aes_ccm_frame, m_state.iteration, m_b))
                {
                    process_ecb_auth_iteration();
                }
                else
                {
                    m_state.iteration      = 0;
                    m_state.transformation = PLAIN_TEXT_AUTH;
                    perform_plain_text_authorization();
                }
                break;

            case PLAIN_TEXT_AUTH:
                perform_plain_text_authorization();
                break;

            case PLAIN_TEXT_ENCRYPT:
                two_blocks_xor(m_m, (uint8_t *)CYPHERTEXT, NRF_802154_ENCRYPT_BLOCK_SIZE);

                len = MIN(m_aes_ccm_frame.plain_text_data_len - offset,
                          NRF_802154_ENCRYPT_BLOCK_SIZE);
                memcpy(m_aes_ccm_frame.plain_text_data + offset, m_m, len);
                offset += NRF_802154_ENCRYPT_BLOCK_SIZE;
                if (plain_text_data_get(&m_aes_ccm_frame, m_state.iteration, m_m))
                {
                    m_state.iteration++;
                    process_ecb_encrypt_iteration();
                }
                else
                {
                    if (m_mic_size[m_aes_ccm_frame.mic_level] != 0)
                    {
                        m_state.iteration      = 0;
                        m_state.transformation = CALCULATE_ENCRYPTED_TAG;
                        process_ecb_encrypt_iteration();
                    }
                    else
                    {
                        m_aes_ccm_frame.raw_frame = NULL;
                    }
                }
                break;

            case CALCULATE_ENCRYPTED_TAG:
                two_blocks_xor(m_auth_tag, (uint8_t *)CYPHERTEXT,
                               m_mic_size[m_aes_ccm_frame.mic_level]);
                memcpy(m_aes_ccm_frame.raw_frame +
                       (m_aes_ccm_frame.raw_frame_len - 2 - m_mic_size[m_aes_ccm_frame.mic_level] +
                        1),
                       m_auth_tag,
                       m_mic_size[m_aes_ccm_frame.mic_level]);
                m_aes_ccm_frame.raw_frame = NULL;
                break;

            default:
                break;
        }
    }
}

/**
 * @brief Start AES-CCM* Authorization Transformation
 */
static void start_ecb_auth_transformation(void)
{
    memcpy(nrf_ecb_data_pointer_get(NRF_ECB) + 16, m_x, 16);
    m_state.iteration       = 0;
    m_state.transformation  = ADD_AUTH_DATA_AUTH;
    NRF_ECB->EVENTS_ENDECB  = 0;
    NRF_ECB->TASKS_STARTECB = 1;
}

/**
 * @brief Initializationsetup of ECB block
 *
 * @return true - block was initialized, false - initialization failed
 */
static bool init_ecb_operation(void)
{
    bool result = true;

    result = nrf_ecb_init();

    if (!result)
    {
        return false;
    }

    nrf_ecb_int_enable(NRF_ECB, NRF_ECB_INT_ENDECB_MASK);
    NVIC_ClearPendingIRQ(ECB_IRQn);
    NVIC_EnableIRQ(ECB_IRQn);

    return result;
}

void nrf_802154_encrypt_aes_ccm_auth_transform(const nrf_802154_encrypt_aes_ccm_frame_t * p_frame)
{
    if (p_frame != &m_aes_ccm_frame)
    {
        memcpy(&m_aes_ccm_frame, p_frame, sizeof(nrf_802154_encrypt_aes_ccm_frame_t));
    }
    uint8_t   auth_flags = auth_flags_format(p_frame);
    uint8_t * p_x;
    uint8_t * p_b;

    p_x = m_x;
    p_b = m_b;

    // initial settings
    memset(p_x, 0, NRF_802154_ENCRYPT_BLOCK_SIZE);
    b0_format(p_frame, auth_flags, p_b);

    two_blocks_xor(p_x, p_b, NRF_802154_ENCRYPT_BLOCK_SIZE);
    init_ecb_operation();
    memset((uint8_t *)ECBKEY, 0, 48);
    nrf_ecb_set_key(m_aes_ccm_frame.key);
    start_ecb_auth_transformation();
}

void nrf_802154_encrypt_aes_ccm_set_key(const uint8_t * p_key)
{
    if (p_key != NULL)
    {
        memcpy(&m_auth_key, p_key, NRF_802154_ENCRYPT_BLOCK_SIZE);
        m_aes_ccm_frame.key = m_auth_key;
    }
}

void nrf_802154_encrypt_aes_ccm_set_nonce(const uint8_t * p_nonce)
{
    if (p_nonce != NULL)
    {
        memcpy(&m_auth_nonce, p_nonce, NRF_802154_ENCRYPT_NONCE_SIZE);
        m_aes_ccm_frame.nonce = m_auth_nonce;
    }
}

void nrf_802154_encrypt_schedule_aes_ccm_auth_transform(
    const nrf_802154_encrypt_aes_ccm_frame_t * p_frame)
{
    // Check if all needed data are available
    if (p_frame->auth_data == NULL)
    {
        return;
    }

    if (p_frame->key == NULL)
    {
        return;
    }

    if (p_frame->plain_text_data == NULL)
    {
        return;
    }

    if (p_frame->nonce == NULL)
    {
        return;
    }

    if (p_frame->raw_frame == NULL)
    {
        return;
    }

    // Check if security level is in range
    if (p_frame->mic_level >= (sizeof(m_mic_size) / sizeof(m_mic_size[0])))
    {
        return;
    }

    memcpy(&m_aes_ccm_frame, p_frame, sizeof(nrf_802154_encrypt_aes_ccm_frame_t));
    nrf_802154_encrypt_aes_ccm_set_key(p_frame->key);
    nrf_802154_encrypt_aes_ccm_set_nonce(p_frame->nonce);
}

void nrf_802154_encrypt_aes_ccm_auth_transform_trigger(const uint8_t * p_frame)
{
    if (p_frame == m_aes_ccm_frame.raw_frame && m_aes_ccm_frame.raw_frame != NULL)
    {
        nrf_802154_encrypt_aes_ccm_auth_transform(&m_aes_ccm_frame);
    }
}

#ifdef ENCRYPT_TX_STARTED

void nrf_802154_tx_started(const uint8_t * p_frame)
{
    nrf_802154_encrypt_aes_ccm_auth_transform_trigger(p_frame);
}

#endif // ENCRYPT_TX_STARTED