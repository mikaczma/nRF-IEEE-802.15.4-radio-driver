/* Copyright (c) 2016-2019 Nordic Semiconductor ASA
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
 *  Module that contains Security Key Manager for the 802.15.4 radio driver for the nRF SoC devices.
 *  Based on IEEE Standard for Low-Rate Wireless Networks  - IEEE Std 802.15.4-2015
 */

#ifndef NRF_802154_SEC_KEY_MANAGER_H_
#define NRF_802154_SEC_KEY_MANAGER_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FRAME_COUNTER_LENGTH 4  ///< As defined in 802.15.4 Std - Chapter 9.4.2 & Table 9-10
#define KEY_LENGTH           16 ///< As defined in 802.15.4 Std - Table 9-10
#define EXTENDED_ADDR_LENGTH 8  ///< As defined in 802.15.4 Std - Chapter 7.1
#define SHORT_ADDR_LENGTH    2  ///< As defined in 802.15.4 Std - Table 9-14
#define PAN_ID_LENGTH        2  ///< As defined in 802.15.4 Std - Table 9-14

// As defined in 802.15.4-2015 Std Table 9-2
typedef enum
{
    NONE     = 0x00,
    SHORT    = 0x02,
    EXTENDED = 0x03
} sec_key_device_addr_mode_t;

// IE type as defined in 802.15.4-2015 Std Chapter 7.4.1
typedef enum
{
    HEADER,
    PAYLOAD,
    NESTED_SHORT,
    NESTED_LONG
} sec_key_ie_t;

// As defined in 802.15.4-2015 Std Table 9-13
typedef struct
{
    sec_key_ie_t key_ie_type;
    uint8_t      key_ie_id;
} nrf_802154_sec_key_manager_key_ie_usage_descriptor_t;

// As defined in 802.15.4-2015 Std Table 9-12
typedef struct
{
    uint8_t key_usage_frame_type;
    uint8_t key_usage_command_id;

} nrf_802154_sec_key_manager_key_usage_descriptor_t;

// As defined in 802.15.4-2015 Std Table 9-11
typedef struct
{
    uint8_t device_extended_address[EXTENDED_ADDR_LENGTH];
    uint8_t device_frame_counter[FRAME_COUNTER_LENGTH];
} nrf_802154_sec_key_manager_key_device_frame_counter_t;

// As defined in 802.15.4-2015 Std Table 9-10
typedef struct
{
    nrf_802154_sec_key_manager_key_usage_descriptor_t     * key_usage_descriptor_list;
    uint8_t                                                 key[KEY_LENGTH];
    uint32_t                                                key_frame_counter;
    bool                                                    frame_counter_per_key;
    nrf_802154_sec_key_manager_key_device_frame_counter_t * key_device_frame_counter_list;
} nrf_802154_sec_key_manager_key_descriptor_t;

// As defined in 802.15.4-2015 Std Table 9-9
typedef struct
{
    uint8_t                                     key_id_mode;
    uint8_t                                   * key_source; // < Present only if key_id_mode is equal to 0x02 (4 bytes long) or 0x03 (8 bytes long)
    uint8_t                                     key_index;
    sec_key_device_addr_mode_t                  key_device_addr_mode;
    uint8_t                                     key_device_pan_id[PAN_ID_LENGTH];
    uint8_t                                   * key_device_address; // < Present only if key_id_mode is equal to 0x00 & in range specified by key_device_addr_mode
    nrf_802154_sec_key_manager_key_descriptor_t key_descriptor;
} nrf_802154_sec_key_manager_key_id_lookup_descriptor_t;

/**
 * @brief   Update and store procedure for frame counter as defined in 802.15.4-2015 Std Chapter 9.2.1g)
 *
 * @param[in] p_key_descriptor - Pointer to key descriptor
 * @param[in] is_tsch_mode - value to check if device is running in TSCH mode
 */
void nrf_802154_sec_key_manager_frame_counter_store(
    nrf_802154_sec_key_manager_key_descriptor_t * p_key_descriptor,
    bool                                          is_tsch_mode);

/**
 * @brief   Check procedure for frame counter as defined in 802.15.4-2015 Std Chapter 9.2.1d)
 *
 * @param[in] p_key_descriptor - Pointer to key descriptor
 * @param[in] is_tsch_mode - value to check if device is running in TSCH mode
 *
 * @retval true - if frame counter is not overused
 * @retval false - if frame counter overflow
 */
bool nrf_802154_sec_key_manager_frame_counter_check(
    nrf_802154_sec_key_manager_key_descriptor_t * p_key_descriptor,
    bool                                          is_tsch_mode);

/**
 * @brief   Set lookup list from higher layer
 *
 * @note perform assignment of externally allocated lookup list
 *
 * @param[in] p_key_id_lookup_list - Pointer to externally allocated key lookup list
 * @param[in] list_length - Value of number of entries in the list
 */
void nrf_802154_sec_key_manager_lookup_list_set(
    nrf_802154_sec_key_manager_key_id_lookup_descriptor_t * p_key_id_lookup_list,
    size_t                                                  list_length);

/**
 * @brief   KeyDescriptor lookup procedure
 * IEEE std 802.15.4-2015 - Chapter 9.2.2
 *
 * @param[in] p_frame - pointer to frame for which will Key Desriptor is get
 * @param[in] key_id_mode - value of given KeyIdMode as defined in 802.15.4-2015 Std Table 9-7
 * @param[in] p_key_source - pointer to KeySource as defined in 802.15.4-2015 Std Chapter 9.4.3.1
 * @param[in] key_index - value of given KeyIndex as defined in 802.15.4-2015 Std Chapter 9.4.3.2
 * @param[in] device_addr_mode - value of given DeviceAddressingMode as defined in 802.15.4-2015 Std Table 9-2
 * @param[in] p_device_pan_id - pointer to given PAN ID as specified in 802.15.4-2015 Std Table 9-9
 * @param[in] p_device_addr - pointer to given Device Address as specified in 802.15.4-2015 Std Table 9-9
 * @param[out] p_key_id_lookup_descriptor - pointer to requested KeyDescriptor as defined in 802.15.4-2015 Std Table 9-10
 *
 * @retval true Status of procedure is SUCCESS and key descriptor is given
 * @retval false Status of procedure is FAILED and key descriptor is NULL
 */
bool nrf_802154_sec_key_manager_lookup_procedure(
    const uint8_t                                * p_frame,
    uint8_t                                        key_id_mode,
    uint8_t                                      * p_key_source,
    uint8_t                                        key_index,
    sec_key_device_addr_mode_t                     device_addr_mode,
    uint8_t                                      * p_device_pan_id,
    uint8_t                                      * p_device_addr,
    nrf_802154_sec_key_manager_key_descriptor_t ** pp_key_descriptor);

#endif /* NRF_802154_SEC_KEY_MANAGER_H_ */
