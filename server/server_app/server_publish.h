/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Descripton: process in enclave client data before publishing
 */

#include "sample_libcrypto.h"
#include "sgx_eid.h"
#include "config_macros.h" 
#include HTTPLIB_PATH

// Structure of the message sent by acess point (used by teh server)
typedef struct iot_message_t
{
    char pk[9];
    char type[7];
    uint32_t encrypted_size;
    uint8_t* encrypted;
} iot_message_t;

// Parse request string and fill fields
iot_message_t parse_request(uint32_t , char* );

// Call enclave to process data inside it
uint32_t secure_msg_processing (iot_message_t , sgx_enclave_id_t , uint8_t* );

// Write into file-based database backup
void file_write (iot_message_t , uint8_t* , uint32_t );

// Get publish message sent by HTTP header
uint32_t get_publish_message(const httplib::Request& , char* );

// Get data, process it and write to database
int server_publish(bool, const httplib::Request&, httplib::Response&, sgx_enclave_id_t);