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
 *  Module that contains CSL injection for the 802.15.4 radio driver for the nRF SoC devices.
 *  Based on IEEE Standard for Low-Rate Wireless Networks  - IEEE Std 802.15.4-2015
 */

#ifndef NRF_802154_CSL_PHASE_INJECTOR_H_
#define NRF_802154_CSL_PHASE_INJECTOR_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Update CSL Phase field in IE header
 * IEEE std 802.15.4-2015 - According to 6.12.2 and 7.4.2.3
 *
 * @param[in] p_ie_csl_header Pointer to IE CSL header
 */
bool nrf_802154_csl_phase_injector_ie_csl_header_phase_update(uint8_t * p_ie_csl_header);

/**
 * @brief Callback to tx_started notification
 *        During this callback transformation is started
 *
 * @param[in] p_frame pointer to raw transmitted frame
 */
void nrf_802154_tx_started(const uint8_t * p_frame);

#endif /* NRF_802154_CSL_PHASE_INJECTOR_H_ */
