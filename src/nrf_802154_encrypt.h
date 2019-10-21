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
 *  Module that contains AES-CCM* encryption for the 802.15.4 radio driver for the nRF SoC devices.
 *  Based on IEEE Standard for Low-Rate Wireless Networks  - IEEE Std 802.15.4-2015
 */

#ifndef NRF_802154_ENCRYPT_H_
#define NRF_802154_ENCRYPT_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NRF_802154_ENCRYPT_L_VALUE                2                                 // Annex B3.2 Mode of operation d)
#define NRF_802154_ENCRYPT_BLOCK_SIZE             16                                // Annex B4 Specification of generic CCM* a)
#define NRF_802154_ENCRYPT_NONCE_SIZE             (15 - NRF_802154_ENCRYPT_L_VALUE) // Annex B4.1 CCM* mode encryption and authentication transformation b)
#define NRF_802154_ENCRYPT_ADATA_AUTH_FLAG        (0x40)                            // Annex B4.1.2 - Adata flag for authentication transform
#define NRF_802154_ENCRYPT_M_BITS_AUTH_FLAG       3                                 // Annex B4.1.2 - Nr of bits for MIC flag for authentication transform

#define NRF_802154_ENCRYPT_AI_FIELD_FLAG_OCTET    0                                 // AnnnexB4.1.3b) - Position of octet for flags in Ai field
#define NRF_802154_ENCRYPT_AI_FIELD_NONCE_OCTET   1                                 // AnnnexB4.1.3b) - Position of octet for nonce in Ai field
#define NRF_802154_ENCRYPT_B0_FIELD_FLAG_OCTET    0                                 // AnnnexB4.1.2b) - Position of octet for flags in B0 field
#define NRF_802154_ENCRYPT_B0_FIELD_NONCE_OCTET   1                                 // AnnnexB4.1.2b) - Position of octet for nonce in B0 field
#define NRF_802154_ENCRYPT_AUTH_DATA_LENGTH_OCTET 0                                 // AnnnexB4.1.1b) - Position of octet for length of auth data in AddAuthData
#define NRF_802154_ENCRYPT_AUTH_DATA_OCTET        2                                 // AnnnexB4.1.1b) - Position of octet for data of auth data in AddAuthData

/**
 * @brief Structure of frame for AES-CCM*
 */
typedef struct
{
    uint8_t * key;                 ///< Pointer to AES key
    uint8_t * auth_data;           ///< Pointer to AES-CCM* authorization data
    uint64_t  auth_data_len;       ///< Length of AES-CCM* authorization data
    uint8_t * plain_text_data;     ///< Pointer to AES-CCM* plain data for encryption and authorization
    uint8_t   plain_text_data_len; ///< Length of plain data
    uint8_t * nonce;               ///< Pointer to AES-CCM* nonce data
    uint8_t   mic_level;           ///< Security level of AES-CCM* transformation of mic_size_t [check 802.15.4-2015 Standard Table 9.6 - up to level 3]
    ///< Possible values of mic_level for AES-CCM* 802.15.4-2016 as is in Annex B3.2e) :
    ///< - Level 0 - MIC_NONE - no authorization
    ///< - Level 1 - MIC_32 - 2 octet long authorization
    ///< - Level 2 - MIC_64 - 4 octet long authorization
    ///< - Level 3 - MIC_128 - 8 octet long authrorization
    uint8_t * raw_frame;     ///< Pointer to raw transmitted frame [including frame size byte at begining]
    uint8_t   raw_frame_len; ///< Length of raw transmitted frame [including frame size byte]
} nrf_802154_encrypt_aes_ccm_frame_t;

/**
 * @brief Set key for AES-CCM* encryption
 *
 * @param[in] p_key pointer to 16-byte long key
 */
void nrf_802154_encrypt_aes_ccm_set_key(const uint8_t * p_key);

/**
 * @brief  Set nonce for AES-CCM* encryption
 *
 * @param[in] p_nonce pointer to NONCE_SIZE byte long nonce
 */
void nrf_802154_encrypt_aes_ccm_set_nonce(const uint8_t * p_nonce);

/**
 * @brief   Algorithm of authentication transformation
 * IEEE std 802.15.4-2015, B.4.1.2 Authentication transformation
 *
 * @param[in] p_frame pointer to AES CCM frame structure
 */
void nrf_802154_encrypt_aes_ccm_auth_transform(const nrf_802154_encrypt_aes_ccm_frame_t * p_frame);

/**
 * @brief Schedule AES-CCM* 2015 standard authorization transformation
 *
 * @param[in] p_frame frame for AES-CCM*
 */
void nrf_802154_encrypt_schedule_aes_ccm_auth_transform(
    const nrf_802154_encrypt_aes_ccm_frame_t * p_frame);

/**
 * @brief Callback to tx_started notification
 *        During this callback transformation is started
 *
 * @param[in] p_frame pointer to raw transmitted frame
 */
void nrf_802154_tx_started(const uint8_t * p_frame);

#endif /* NRF_802154_ENCRYPT_H_ */
