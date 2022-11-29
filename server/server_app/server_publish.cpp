/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Descripton: process in enclave client data before publishing
 */

#include <stdlib.h>
#include <iostream>
#include <string.h>
#include <string>
#include <stdexcept>
#include <limits>
#include <stdio.h>
#include <chrono>
#include <thread>
#include "timer.h"

#include "errors.h"
#include "server_publish.h"
#include "server_processing.h"
#include "server_disk_manager.h"

#include "sample_libcrypto.h"   // sample_aes_gcm_128bit_key_t
#include "config_macros.h"      // ULTRALIGH_SAMPLE
#include "utils_sgx.h"
#include "utils.h"
#include "server_enclave_u.h"
//#include "ecp.h"                // sample_ec_key_128bit_t
#include HTTPLIB_PATH

#include "sgx_urts.h"
#include "sgx_eid.h"
#include "sgx_ukey_exchange.h"
#include "sgx_uae_epid.h"
#include "sgx_uae_quote_ex.h"
#include "sgx_tcrypto.h"

using namespace httplib;

void ocall_print_secret(uint8_t* secret, uint32_t secret_size)
{
    uint32_t i;
    char hex_number[5];
    for (i=0;i<secret_size;i++)
    {
        sprintf(hex_number, "%x", secret[i]);
        printf("%s ", hex_number);
    }
    printf("\n");
}
 
void ocall_print_aggregated(unsigned long number) {
    printf("Aggregated: %lu\n", number);
}

// pk|72d41281|type|123456|size|62|encrypted|...
server_error_t parse_request(char* msg, iot_message_t* p_rcv_msg)
{
    Timer t("parse_request");   
    if(DEBUG) printf("\nParsing publication message fields\n");
    
    char* token = strtok_r(msg, "|", &msg);
    int i = 0;
    char auxiliar[3];
    char* invalid_char;
    while (token != NULL)
    {
        i++;
        token = strtok_r(NULL, "|", &msg);

        // Get client key
        if (i == 1){
            memcpy(p_rcv_msg->pk, token, 8);
            p_rcv_msg->pk[8] = '\0';

            if(DEBUG) printf("pk: %s\n", p_rcv_msg->pk);
        }

        // Get data type
        if (i == 3) {
            memcpy(p_rcv_msg->type, token, 6);
            p_rcv_msg->type[6] = '\0';

            if(DEBUG) printf("type: %s\n", p_rcv_msg->type);
        }

        // Get encrypted message size
        if (i == 5) {
            p_rcv_msg->encrypted_size = (uint32_t)strtoul(token, &invalid_char, 16);

            if(*invalid_char != 0)
                return print_error_message(INVALID_ENCRYPTED_SIZE_FIELD_ERROR);

            if(DEBUG) printf("encrypted_size: %u\n", p_rcv_msg->encrypted_size);
        }

        // Get encrypted message
        if (i == 7) {

            if(DEBUG) printf("encrypted: ");

            p_rcv_msg->encrypted = (uint8_t*)malloc((p_rcv_msg->encrypted_size+1) * sizeof(uint8_t));

            for (uint32_t j=0; j<p_rcv_msg->encrypted_size; j++){
                auxiliar[0] = token[3*j];
                auxiliar[1] = token[3*j+1];
                auxiliar[2] = '\0';
                p_rcv_msg->encrypted[j] = (uint8_t)strtoul(auxiliar, &invalid_char, 16);

                if(auxiliar != 0 && *invalid_char != 0) {
                    free(p_rcv_msg->encrypted);
                    return print_error_message(INVALID_ENCRYPTED_FIELD_ERROR);
                }

                if(DEBUG) printf("%02x,", (unsigned)p_rcv_msg->encrypted[j]);
            }
            p_rcv_msg->encrypted[p_rcv_msg->encrypted_size] = '\0';
            if(DEBUG) printf("\n");
        }
    }

    return OK;
}

server_error_t get_publish_message(const Request& req, char* snd_msg, uint32_t* p_size)
{
    Timer t("get_publish_message");
    if(DEBUG) printf("\nGetting publish message fields:\n");

    std::string size_field = req.matches[1].str();

    try {
        *p_size = (uint32_t)std::stoul(size_field);
    }
    catch (std::invalid_argument& exception) {
        return print_error_message(INVALID_HTTP_MESSAGE_SIZE_FIELD_ERROR);
    }

    if(*p_size > URL_MAX_SIZE)
        return print_error_message(HTTP_MESSAGE_SIZE_OVERFLOW_ERROR);

    if(DEBUG) printf("Size: %u\n", *p_size);

    std::string message_field = req.matches[2].str();

    strncpy(snd_msg, message_field.c_str(), (size_t)(*p_size-1));
    snd_msg[*p_size] = '\0';
    
    if(DEBUG) printf("Message: %s\n", snd_msg);

    return OK;
}

server_error_t server_publish(bool secure, const Request& req, Response& res, sgx_enclave_id_t global_eid)
{
    Timer t("server_publish");
    server_error_t ret = OK;

    // Get message sent in HTTP header
    char* snd_msg = (char*)malloc(URL_MAX_SIZE);

    uint32_t size;
    ret = get_publish_message(req, snd_msg, &size);
    if(ret) {
        free(snd_msg);
        return ret;
    }
 
    // Server receives and separate parameters according to Ultrlight protocol
    // pk|72d41281|type|123456|size|62|encrypted|... 
    iot_message_t rcv_msg;
    ret = parse_request(snd_msg, &rcv_msg);
    free(snd_msg);
    if(ret)
        return ret;

    // Identify data type and call function to process it
    if(!strcmp(rcv_msg.type, "555555")){
        if(DEBUG) printf("\nAggregating\n");
        ret = aggregation(rcv_msg, global_eid, secure); 
    }
    else {
        if(DEBUG) printf("\nPublishing without processing\n");
        ret = no_processing(rcv_msg, global_eid, secure); 
    }

    // Send response
    free(rcv_msg.encrypted);
    if(!ret) {
        if(DEBUG) printf("Sending ack\n");
        res.set_content("0", "text/plain");
    }

    return ret; 
}
