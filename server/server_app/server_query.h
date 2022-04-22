/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Descripton: query message and return for client
 */

#include <stdio.h>
#include "sample_libcrypto.h"
#include "sgx_eid.h"
#include "config_macros.h" 
#include HTTPLIB_PATH

// Register shared key (not used, only for testes)
const sample_aes_gcm_128bit_key_t sha_key[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

// Structure of the message written to database
typedef struct stored_data_t
{
    char pk[9];
    char type[7];
    uint32_t encrypted_size;
    uint8_t* encrypted;
} stored_message_t;

// Parse request string and fill fields
uint32_t parse_request(uint32_t , char* , char*);

// Separate parameters of stored message
stored_data_t get_stored_parameters(char* );

// Locate data in file and read it 
void file_read(uint32_t , char* );

// Get query message sent by HTTP header
uint32_t get_query_message(const httplib::Request& , char* );

// Re-encrypt the data, now using querier key instead of publisher key
uint8_t enclave_get_response(stored_data_t , sgx_enclave_id_t , char* , uint8_t* );

// Mount HTTP response for client
void make_response(uint8_t* , uint32_t , char* );

// Get data, process it and read to database
int server_query(bool, const httplib::Request&, httplib::Response&, sgx_enclave_id_t);