/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Descripton: receive client key and write to disk
 */


#ifndef _SERVER_REGISTER_
#define _SERVER_REGISTER_

#include <stdio.h>
#include "sample_libcrypto.h"
#include "sgx_eid.h"
#include "config_macros.h" 
#include "server.h"
#include "errors.h"
#include HTTPLIB_PATH

// Parse request string and fill fields
server_error_t parse_register(char* , register_message_t*);

// Get register message sent by HTTP header
server_error_t get_register_message(const httplib::Request& , char*, uint32_t* );

// Seal the client key
server_error_t enclave_seal_key(register_message_t, sgx_enclave_id_t, char*);

// Write client key to disk
server_error_t server_register(bool, const httplib::Request&, httplib::Response&, sgx_enclave_id_t);

#endif