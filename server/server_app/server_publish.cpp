/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Descripton: process in enclave client data before publishing
 */

#include <cstdio>
#include <stdlib.h>
#include <iostream>
#include <string.h>
#include <stdio.h>
#include <chrono>
#include <thread>

#include "server_publish.h"
//#include "server_processing.h"
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
            for (uint32_t j=0; j<8; j++)
            {
                rcv_msg.pk[j] = token[j];
            }
            rcv_msg.pk[8] = '\0';
        }
        // Get data type
        if (i == 3)
        {
            for (uint32_t j=0; j<6; j++)
            {
                rcv_msg.type[j] = token[j];
            }
            rcv_msg.type[7] = '\0';
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

uint32_t secure_msg_processing (iot_message_t rcv_msg, sgx_enclave_id_t global_eid, uint8_t* processed_data){

    // Search user file and read sealed key
    char seal_path[PATH_MAX_SIZE];
    sprintf(seal_path, "%s/%s", SEALS_PATH, rcv_msg.pk);
    FILE* seal_file = fopen(seal_path, "rb");
    size_t sealed_size = sizeof(sgx_sealed_data_t) + sizeof(uint8_t)*16;
    uint8_t* sealed_data = (uint8_t*)malloc(sealed_size);
    if (seal_file == NULL) {
        printf("\nWarning: Failed to open the seal file \"%s\".\n", seal_path);
        fclose(seal_file);
        free(sealed_data);
        return 1;
    }
    else {
        fread(sealed_data,1,sealed_size,seal_file);
        fclose(seal_file);
    }

    //Detect processing thath will be applied 
    //proc_code_t proc_code = detect_processing_code(rcv_msg.type);
    unsigned proc_code = 0;

    // Call enclave to unseal key, decrypt with the key, process and return encrypted result
    sgx_status_t ecall_status;
    sgx_status_t sgx_status;
    uint32_t real_size;
    uint32_t decMessageLen = rcv_msg.encrypted_size - (SAMPLE_AESGCM_MAC_SIZE + SAMPLE_AESGCM_IV_SIZE);
    sgx_status = process_data(global_eid, &ecall_status,
        (sgx_sealed_data_t*)sealed_data,            //sealed key 
        rcv_msg.encrypted,                          //data for being decrypted and processed 
        rcv_msg.encrypted_size,                     //encrypted data size
        decMessageLen,                              //bufer size with decrypted data  
        processed_data,                             //data for being published
        (uint32_t)RESULT_MAX_SIZE,                  //buffer max size with data for being published
        &real_size,                                 //data real size
        (unsigned)proc_code                         //processing for being applied               
    );
    return 98;
}

void file_write (iot_message_t rcv_msg, uint8_t* processed_data, uint32_t real_size)
{
    // Write header in disk copy
    // type|123456|size|0x35|encrypted|AES128(pk|72d41281|type|weg_multimeter|payload|250110090|permission1|72d41281)
    char publish_header[5+6+6+4+11+1];
    sprintf(publish_header, "type|%s|size|0x%02x|encrypted|", rcv_msg.type, rcv_msg.encrypted_size);
    char db_path[DB_PATH_SIZE];
    sprintf(db_path, "%s", DB_PATH);
    FILE* db_file = fopen(db_path, "ab");
    if (db_file != NULL) {
        fwrite(publish_header, 1, (size_t)5+6+6+4+11+1, db_file);
    }
    fclose(db_file);

    // Write result in disk copy
    sprintf(db_path, "%s", DB_PATH);
    db_file = fopen(db_path, "ab");
    if (db_file != NULL) {
        fwrite(processed_data, 1, (size_t)real_size, db_file);
        char nl = '\n';
        fwrite(&nl, 1, sizeof(char), db_file);
    }
    fclose(db_file);
}

uint32_t get_publish_message(const Request& req, char* snd_msg)
{
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

    if (secure == false)
    {
        file_write (rcv_msg, rcv_msg.encrypted, rcv_msg.encrypted_size);
    }
    if (secure == true)
    {
        uint8_t processed_data [RESULT_MAX_SIZE];
        uint32_t real_size;
        real_size = secure_msg_processing(rcv_msg, global_eid, processed_data);
        file_write (rcv_msg, processed_data, real_size);
    }
    
    free(rcv_msg.encrypted);
    res.set_content("ack", "text/plain");
    return 0; 
}
