/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Descripton: process in enclave client data before publishing
 */

#include "sample_libcrypto.h"
#include "sgx_eid.h"
#include "config_macros.h" 
#include HTTPLIB_PATH
#include "server.h"

// Parse request string and fill fields
int parse_request(uint32_t , char*, iot_message_t* );

// Get publish message sent by HTTP header
int get_publish_message(const httplib::Request& , char*, uint32_t* );

// Get data, process it and write to database
int server_publish(bool, const httplib::Request&, httplib::Response&, sgx_enclave_id_t);