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
int parse_request(uint32_t size, char* msg, iot_message_t* p_rcv_msg)
{
    Timer t("parse_request");
    
    if(DEBUG) printf("Parsing message fields\n");
    
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

            if(*invalid_char != 0) {
                printf("\nInvalid encrypted size message format.\n");
                return -1;
            }

            if(DEBUG) printf("encrypted_size: %u\n", p_rcv_msg->encrypted_size);
        }

        // Get encrypted message
        if (i == 7) {

            if(DEBUG) printf("encrypted: ");

            p_rcv_msg->encrypted = (uint8_t*)malloc((p_rcv_msg->encrypted_size+1) * sizeof(uint8_t));
            if (p_rcv_msg->encrypted == NULL) {
                printf("\nAllocation error for the encrypted publciation message.\n");
                return -1;
            }

            for (uint32_t j=0; j<p_rcv_msg->encrypted_size; j++){
                auxiliar[0] = token[3*j];
                auxiliar[1] = token[3*j+1];
                auxiliar[2] = '\0';
                p_rcv_msg->encrypted[j] = (uint8_t)strtoul(auxiliar, &invalid_char, 16);

                if(auxiliar != 0 && *invalid_char != 0) {
                    printf("\nInvalid encrypted publciation message format.\n");
                    free(p_rcv_msg->encrypted);
                    return -1;
                }

                if(DEBUG) printf("%02x,", (unsigned)p_rcv_msg->encrypted[j]);
            }
            p_rcv_msg->encrypted[p_rcv_msg->encrypted_size] = '\0';
        }
    }

    return 0;
}

int get_publish_message(const Request& req, char* snd_msg, uint32_t* p_size)
{
    Timer t("get_publish_message");

    std::string size_field = req.matches[1].str();

    try {
        *p_size = (uint32_t)std::stoul(size_field);
    }
    catch (std::invalid_argument& exception) {
        printf("\nFailed to detect HTTP message size\n");
        return -1;
    }

    if(*p_size > URL_MAX_SIZE) {
        printf("\nHTTP message bigger than the maximum size\n");
        return -1;
    }

    if(DEBUG) printf("Size: %u\n", *p_size);

    std::string message_field = req.matches[2].str();

    strncpy(snd_msg, message_field.c_str(), (size_t)(*p_size-1));
    snd_msg[*p_size] = '\0';
    
    if(DEBUG) printf("Message: %s\n\n", snd_msg);

    return 0;
}

int server_publish(bool secure, const Request& req, Response& res, sgx_enclave_id_t global_eid)
{
    Timer t("server_publish");

    // Get message sent in HTTP header
    char* snd_msg = (char*)malloc(URL_MAX_SIZE*sizeof(char));;

    uint32_t size;
    if(get_publish_message(req, snd_msg, &size)) {
        free(snd_msg);
        return -1;
    }
 
    // Server receives and separate parameters according to Ultrlight protocol
    // pk|72d41281|type|123456|size|62|encrypted|... 
    iot_message_t rcv_msg;
    if(parse_request(size, snd_msg, &rcv_msg))
        return -1;
    free(snd_msg);

    // Identify data type and call function to process it
    if(!strcmp(rcv_msg.type, "555555")){

        if(DEBUG) printf("\n\nAggregating\n");

        if(aggregation(rcv_msg, global_eid, secure)){
            free(rcv_msg.encrypted);
            return -1;
        }
    }
    else {

        if(DEBUG) printf("\nPublishing without processing\n");

        if(no_processing(rcv_msg, global_eid, secure)){
            free(rcv_msg.encrypted); 
            return -1;
        } 
    }

    free(rcv_msg.encrypted);

    if(DEBUG) printf("Sending ack\n");
    res.set_content("ack", "text/plain");
    return 0; 
}
