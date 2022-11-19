/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Descripton: query message and return for client
 */

#include <stdio.h>
#include "sample_libcrypto.h"
#include "sgx_eid.h"
#include "config_macros.h" 
#include "server.h"
#include HTTPLIB_PATH

// Parse request string and fill fields
int parse_request(char*, char*, char*, uint32_t*);

// Get query message sent by HTTP header
int get_query_message(const httplib::Request& , char*, uint32_t* );

// Re-encrypt the data, now using querier key instead of publisher key
int enclave_get_response(stored_data_t, sgx_enclave_id_t, uint8_t*, char*, uint8_t*);

int get_response(stored_data_t, uint8_t*, char*, uint8_t*);

// Mount HTTP response for client
void make_response(uint8_t*, uint32_t, char*);

// Get data, process it and read to database
int server_query(bool, const httplib::Request&, httplib::Response&, sgx_enclave_id_t);