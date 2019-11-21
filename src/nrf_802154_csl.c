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
 *  This file implements CSL injection for the nRF 802.15.4 radio driver.
 *  Based on IEEE Standard for Low-Rate Wireless Networks  - IEEE Std 802.15.4-2015
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "nrf_802154_csl.h"
#include "rsch/nrf_802154_rsch.h"
#include "mac_features/nrf_802154_frame_parser.h"
#include "nrf_802154_encrypt.h"

#define IE_CSL_HEADER_PHASE_BYTE 2 ///< IE CSL Header Phase octet position

/**
 * @brief   Update CSL Phase field
 * IEEE std 802.15.4-2015, B.4.1.2 Authentication transformation
 *
 * @param[in] p_frame Pointer to IE CSL header
 * @param[in] phase   Value of actual CSL phase given in symbols
 */
static void nrf_802154_csl_phase_update(const uint8_t * p_ie_csl_header, uint16_t phase)
{
    *(uint16_t *)(p_ie_csl_header + IE_CSL_HEADER_PHASE_BYTE) = phase / 10;
}

void nrf_802154_tx_started(const uint8_t * p_frame)
{
    if (nrf_802154_frame_parser_is_csl_ie_header_available(p_frame))
    {
        const uint8_t * p_ie_csl_header = nrf_802154_frame_parser_csl_ie_header_get(p_frame);

        uint32_t phase = nrf_802154_rsch_get_next_scheduled_receive_symbols();

        nrf_802154_csl_phase_update(p_ie_csl_header, phase);
    }

    if (nrf_802154_frame_parser_security_enabled_bit_is_set(p_frame))
    {
        nrf_802154_encrypt_aes_ccm_auth_transform_trigger(p_frame);
    }
}
