/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Descripton: receive client key and write to disk
 */


#include <stdio.h>
#include "sample_libcrypto.h"
#include "sgx_eid.h"
#include "config_macros.h" 
#include "server.h"
#include HTTPLIB_PATH

// Parse request string and fill fields
int parse_request(uint32_t , char* , char*, uint32_t*);

// Get register message sent by HTTP header
int get_register_message(const httplib::Request& , char*, uint32_t* );

// Seal the client key
int enclave_seal_key(register_message_t, sgx_enclave_id_t, char*);

// Write client key to disk
int server_register(bool, const httplib::Request&, httplib::Response&, sgx_enclave_id_t);