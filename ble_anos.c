/**
 * Copyright (c) 2012 - 2021, Nordic Semiconductor ASA
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form, except as embedded into a Nordic
 *    Semiconductor ASA integrated circuit in a product or a software update for
 *    such product, must reproduce the above copyright notice, this list of
 *    conditions and the following disclaimer in the documentation and/or other
 *    materials provided with the distribution.
 *
 * 3. Neither the name of Nordic Semiconductor ASA nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * 4. This software, with or without modification, must only be used with a
 *    Nordic Semiconductor ASA integrated circuit.
 *
 * 5. Any software provided in binary form under this license must not be reverse
 *    engineered, decompiled, modified and/or disassembled.
 *
 * THIS SOFTWARE IS PROVIDED BY NORDIC SEMICONDUCTOR ASA "AS IS" AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY, NONINFRINGEMENT, AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL NORDIC SEMICONDUCTOR ASA OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
#include "sdk_common.h"

#include "ble.h"
//#include "ble_nus.h"
#include "ble_srv_common.h"

#define NRF_LOG_MODULE_NAME ble_nus
#if BLE_NUS_CONFIG_LOG_ENABLED
#define NRF_LOG_LEVEL       BLE_NUS_CONFIG_LOG_LEVEL
#define NRF_LOG_INFO_COLOR  BLE_NUS_CONFIG_INFO_COLOR
#define NRF_LOG_DEBUG_COLOR BLE_NUS_CONFIG_DEBUG_COLOR
#else // BLE_NUS_CONFIG_LOG_ENABLED
#define NRF_LOG_LEVEL       0
#endif // BLE_NUS_CONFIG_LOG_ENABLED
#include "nrf_log.h"
NRF_LOG_MODULE_REGISTER();

#define BLE_UUID_ANOS_SERVICE 0x0001 
#define BLE_UUID_ANOS_CHARACTERISTIC 0x0001               /**< The UUID of the TX Characteristic. */


#define BLE_NUS_MAX_RX_CHAR_LEN        BLE_NUS_MAX_DATA_LEN /**< Maximum length of the RX Characteristic (in bytes). */
#define BLE_NUS_MAX_TX_CHAR_LEN        BLE_NUS_MAX_DATA_LEN /**< Maximum length of the TX Characteristic (in bytes). */

#define ANOS_BASE_UUID                  {{0x85, 0x2A, 0x9F, 0x57, 0xC5, 0x2A, 0xED, 0x88, 0x26, 0xC2, 0xF4, 0x12, 0x00, 0x00, 0x19, 0x15}} /**< Used vendor specific UUID. */
#define ANOS_CHARACTERISTIC_BASE_UUID      {{0x0E, 0x68, 0x21, 0x74, 0x37, 0x48, 0x61, 0xBF, 0x92, 0xFB, 0x68, 0x1D, 0x00, 0x00, 0x0C, 0x8E}} /**< Used vendor specific UUID. */


struct ble_anos_s
{
    uint8_t                         uuid_type;          /**< UUID type for Nordic UART Service Base UUID. */
    uint16_t                        service_handle;     /**< Handle of Nordic UART Service (as provided by the SoftDevice). */
    ble_gatts_char_handles_t        ano_handles;         /**< Handles related to the TX characteristic (as provided by the SoftDevice). */

};
typedef struct ble_anos_s ble_anos_t;

uint32_t ble_anos_init(ble_anos_t * p_anos)
{
    ret_code_t            err_code;
    ble_uuid_t            ble_uuid;
    ble_uuid128_t         anos_base_uuid = ANOS_BASE_UUID;
    ble_add_char_params_t add_char_params;

    ble_uuid128_t         gfp_character_base_uuid = ANOS_CHARACTERISTIC_BASE_UUID;

    uint8_t               character_uuid_type=0;

    VERIFY_PARAM_NOT_NULL(p_anos);
    

    /**@snippet [Adding proprietary Service to the SoftDevice] */
    // Add a custom base UUID.
    err_code = sd_ble_uuid_vs_add(&anos_base_uuid, &p_anos->uuid_type);
    VERIFY_SUCCESS(err_code);

    ble_uuid.type = p_anos->uuid_type;
    ble_uuid.uuid = BLE_UUID_ANOS_SERVICE;

    // Add the service.
    err_code = sd_ble_gatts_service_add(BLE_GATTS_SRVC_TYPE_PRIMARY,
                                        &ble_uuid,
                                        &p_anos->service_handle);
    /**@snippet [Adding proprietary Service to the SoftDevice] */
    VERIFY_SUCCESS(err_code);


    err_code = sd_ble_uuid_vs_add(&gfp_character_base_uuid, &character_uuid_type);
    VERIFY_SUCCESS(err_code);

    // Add the RX Characteristic.
    memset(&add_char_params, 0, sizeof(add_char_params));
    add_char_params.uuid                     = BLE_UUID_ANOS_CHARACTERISTIC;
    add_char_params.uuid_type                = character_uuid_type;
    add_char_params.max_len                  = 100;
    add_char_params.init_len                 = sizeof(uint8_t);
    add_char_params.is_var_len               = true;
    add_char_params.char_props.indicate = 1;
    add_char_params.char_props.write  = 1;
    //add_char_params.char_props.read   = 1;
    //add_char_params.is_defered_read = true;
    add_char_params.is_defered_write = true;
    add_char_params.read_access       = SEC_OPEN;
    add_char_params.write_access      = SEC_OPEN;
    add_char_params.cccd_write_access = SEC_OPEN;

    err_code = characteristic_add(p_anos->service_handle, &add_char_params, &p_anos->ano_handles);
    if (err_code != NRF_SUCCESS)
    {
        return err_code;
    }


}





