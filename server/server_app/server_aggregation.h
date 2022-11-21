/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Description: aggregate client data
 */

#include <stdlib.h>
#include <iostream>
#include <string.h>
#include <stdio.h>
#include <chrono>
#include <thread>
#include "timer.h"

#include "sample_libcrypto.h"   // sample_aes_gcm_128bit_key_t
#include "config_macros.h"      // ULTRALIGH_SAMPLE
#include "utils_sgx.h"
#include "utils.h"
#include "encryption.h"
#include "server_enclave_u.h"
#include "server.h"
//#include "ecp.h"                // sample_ec_key_128bit_t

#include "sgx_urts.h"
#include "sgx_eid.h"
#include "sgx_ukey_exchange.h"
#include "sgx_uae_epid.h"
#include "sgx_uae_quote_ex.h"
#include "sgx_tcrypto.h"

int sum_encrypted_data_i(uint8_t*, uint32_t, uint8_t*, uint8_t*, uint8_t**, uint32_t, char*, uint8_t*, uint32_t* );

int get_db_request_i(iot_message_t, uint8_t*, char*);