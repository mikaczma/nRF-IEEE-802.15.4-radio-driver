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
 *  This file implements Security Key Manager for the nRF 802.15.4 radio driver.
 *  Based on IEEE Standard for Low-Rate Wireless Networks  - IEEE Std 802.15.4-2015
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include "nrf_802154_sec_key_manager.h"
#include "nrf_802154_frame_parser.h"
#include "../nrf_802154_pib.h"
#include "../nrf_802154_const.h"

static nrf_802154_sec_key_manager_key_id_lookup_descriptor_t * mp_key_id_lookup_list = NULL;
static size_t m_key_id_lookup_list_length = 0; // Amount of entries in the lookup list

void nrf_802154_sec_key_manager_lookup_list_set(
    nrf_802154_sec_key_manager_key_id_lookup_descriptor_t * p_key_id_lookup_list,
    size_t                                                  list_lenght)
{
    mp_key_id_lookup_list       = p_key_id_lookup_list;
    m_key_id_lookup_list_length = list_lenght;
}

bool nrf_802154_sec_key_manager_lookup_procedure(
    const uint8_t                                         * p_frame,
    uint8_t                                                 key_id_mode,
    uint8_t                                               * p_key_source,
    uint8_t                                                 key_index,
    sec_key_device_addr_mode_t                              device_addr_mode,
    uint8_t                                               * p_device_pan_id,
    uint8_t                                               * p_device_addr,
    nrf_802154_sec_key_manager_key_id_lookup_descriptor_t * p_key_id_lookup_descriptor)
{
    if (mp_key_id_lookup_list != NULL)
    {
        switch (key_id_mode)
        {
            case 0x00: // Chapter 9.2.2a)

                for (size_t i = 0; i < m_key_id_lookup_list_length; i++)
                {
                    if (mp_key_id_lookup_list[i].key_id_mode == 0x00)
                    {
                        if ((device_addr_mode == NONE) || (p_device_pan_id == NULL)) // Chapter 9.2.2a)1)
                        {
                            p_device_pan_id = (uint8_t *)nrf_802154_pib_pan_id_get();
                        }

                        uint8_t frame_type = nrf_802154_frame_parser_frame_type_get(p_frame);

                        if ((device_addr_mode == NONE))
                        {
                            if (frame_type == FRAME_TYPE_BEACON) // Chapter 9.2.2a)2)
                            {
                                memcpy(p_device_addr,
                                       nrf_802154_pib_coord_extended_address_get(),
                                       EXTENDED_ADDR_LENGTH);
                            }
                            else // Chapter 9.2.2a)3)
                            {
                                uint8_t coord_short_addr_compare[SHORT_ADDR_LENGTH] = {0xff, 0xff};  // Check coord_short_addr = 0xfffe

                                if (memcmp(nrf_802154_pib_coord_short_address_get(),
                                           coord_short_addr_compare, SHORT_ADDR_LENGTH)) // Chapter 9.2.2a)3)iii)
                                {
                                    return false;
                                }
                                coord_short_addr_compare[1] = 0xfe;                      // Check coord_short_addr = 0xfffe
                                if (memcmp(nrf_802154_pib_coord_short_address_get(),
                                           coord_short_addr_compare, SHORT_ADDR_LENGTH)) // Chapter 9.2.2a)3)i)
                                {
                                    memcpy(p_device_addr,
                                           nrf_802154_pib_coord_extended_address_get(),
                                           EXTENDED_ADDR_LENGTH);
                                }
                                else // Chapter 9.2.2a)3)ii)
                                {
                                    memcpy(p_device_addr, nrf_802154_pib_coord_short_address_get(),
                                           SHORT_ADDR_LENGTH);
                                }
                            }
                        }

                        if ((device_addr_mode == mp_key_id_lookup_list[i].key_device_addr_mode) &&
                            (memcmp(p_device_pan_id, mp_key_id_lookup_list[i].key_device_pan_id,
                                    PAN_ID_LENGTH) == 0)) // Chapter 9.2.2a)4)
                        {
                            uint8_t addr_length = 0;

                            switch (device_addr_mode)
                            {
                                case SHORT:
                                    addr_length = SHORT_ADDR_LENGTH;
                                    break;

                                case EXTENDED:
                                    addr_length = EXTENDED_ADDR_LENGTH;
                                    break;

                                default:
                                    return false;
                                    break;
                            }

                            if (memcmp(p_device_addr, mp_key_id_lookup_list[i].key_device_address,
                                       addr_length) == 0)
                            {
                                p_key_id_lookup_descriptor = &mp_key_id_lookup_list[i];
                                return true;
                            }
                        }
                    }

                }
                break;

            case 0x01:

                for (size_t i = 0; i < m_key_id_lookup_list_length; i++)
                {
                    if (key_index == mp_key_id_lookup_list[i].key_index)
                    {
                        if (mp_key_id_lookup_list[i].key_id_mode == 0x01)
                        {
                            p_key_id_lookup_descriptor = &mp_key_id_lookup_list[i];
                            return true;
                        }
                    }
                }
                break;

            case 0x02: // fallback on purpose as described in 802.15.4-2015 Std 9.2.2c)
            case 0x03:

                for (size_t i = 0; i < m_key_id_lookup_list_length; i++)
                {
                    if ((key_id_mode == mp_key_id_lookup_list[i].key_id_mode) &&
                        (key_index == mp_key_id_lookup_list[i].key_index))
                    {
                        uint8_t key_source_length = 0;

                        switch (mp_key_id_lookup_list[i].key_id_mode)
                        {
                            case 0x02:
                                key_source_length = 4;
                                break;

                            case 0x03:
                                key_source_length = 8;
                                break;

                            default:
                                break;
                        }

                        if (memcmp(p_key_source, mp_key_id_lookup_list[i].key_source,
                                   key_source_length) == 0)
                        {
                            p_key_id_lookup_descriptor = &mp_key_id_lookup_list[i];
                            return true;
                        }
                    }
                }
                break;

            default:
                assert(false);
                break;
        }
    }

    p_key_id_lookup_descriptor = NULL;
    return false;
}
