/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Descripton: process in enclave client data before publishing
 */

#include <stdlib.h>
#include <iostream>
#include <string.h>
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
#include "ecp.h"                // sample_ec_key_128bit_t
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

iot_message_t parse_request(uint32_t size, char* msg)
{
    Timer t("parse_request");
    iot_message_t rcv_msg;
    char* token = strtok_r(msg, "|", &msg);
    int i = 0;
    char auxiliar[3];
    while (token != NULL)
    {
        i++;
        token = strtok_r(NULL, "|", &msg);
        // Get client key
        if (i == 1)
        {
            memcpy(rcv_msg.pk, token, 8);
            rcv_msg.pk[8] = '\0';
        }
        // Get data type
        if (i == 3)
        {
            memcpy(rcv_msg.type, token, 6);
            rcv_msg.type[6] = '\0';
        }
        // Get encrypted message size
        if (i == 5)
        {
            rcv_msg.encrypted_size = (uint32_t)strtoul(token,NULL,16);
        }
        // Get encrypted message
        if (i == 7)
        {
            rcv_msg.encrypted = (uint8_t*)malloc((rcv_msg.encrypted_size+1) * sizeof(uint8_t));
            if (rcv_msg.encrypted == NULL)
            {
                printf("Allocation error\n");
            }
            for (uint32_t j=0; j<rcv_msg.encrypted_size; j++)
            {
                auxiliar[0] = token[6*j+2];
                auxiliar[1] = token[6*j+3];
                auxiliar[2] = '\0';
                rcv_msg.encrypted[j] = (uint8_t)strtoul(auxiliar, NULL, 16);
            }
            rcv_msg.encrypted[rcv_msg.encrypted_size] = 0;
        }
    }
    return rcv_msg;
}

uint32_t get_publish_message(const Request& req, char* snd_msg)
{
    Timer t("get_publish_message");
    char c_size[4];
    uint32_t size;
    std::string a_size = req.matches[1].str();
    strcpy(c_size, a_size.c_str());
    size = (uint32_t)strtoul(c_size, NULL, 10);

    std::string a_snd_msg = req.matches[2].str();
    strncpy(snd_msg, a_snd_msg.c_str(), (size_t)(size-1));
    snd_msg[size] = '\0';

    return size;
}

int server_publish(bool secure, const Request& req, Response& res, sgx_enclave_id_t global_eid)
{
    Timer t("server_publish");
    // Get message sent in HTTP header
    uint32_t size;
    char* snd_msg = (char*)malloc(URL_MAX_SIZE*sizeof(char));;
    size = get_publish_message(req, snd_msg);
    //printf("Request size = %u\nRequest msg = %s\n", size, snd_msg);
 
    // Server receives and separate parameters according to Ultrlight protocol
    // type|123456|size|0x35|encrypted|AES128(pk|72d41281|type|weg_multimeter|payload|250110090|permission1|72d41281)    
    iot_message_t rcv_msg;
    rcv_msg = parse_request(size, snd_msg);
    free(snd_msg);

    // Identify data type and call function to process it
    if(!strcmp(rcv_msg.type, "555555"))
        aggregation(rcv_msg, global_eid, secure);
    else
        no_processing(rcv_msg, global_eid, secure);

    free(rcv_msg.encrypted);
    res.set_content("ack", "text/plain");
    return 0; 
}
