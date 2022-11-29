/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Descripton: remove data
 */

#ifndef _SERVER_REVOKE_
#define _SERVER_REVOKE_

#include <stdio.h>
#include "sample_libcrypto.h"
#include "sgx_eid.h"
#include "config_macros.h" 
#include "server.h"
#include "errors.h"
#include HTTPLIB_PATH

server_error_t parse_revocation(char*, access_message_t* );

server_error_t verify_deletion(stored_data_t, access_message_t, uint8_t* );

server_error_t enclave_verify_deletion(stored_data_t, sgx_enclave_id_t, access_message_t, uint8_t* ); 

// Get revocation message
server_error_t get_revocation_message(const httplib::Request& req, char* snd_msg, uint32_t* p_size);

// Get data and remove from database
server_error_t server_revoke(bool, const httplib::Request&, httplib::Response&, sgx_enclave_id_t);

#endif