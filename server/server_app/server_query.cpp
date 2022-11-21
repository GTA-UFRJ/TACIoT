/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Descripton: query message and return for client
 */

#include <cstdio>
#include <stdlib.h>
#include <iostream>
#include <string.h>
#include <stdio.h> 
#include <chrono>
#include <thread>
#include "timer.h"

#include "server_query.h"
#include "server_processing.h"
#include "server_disk_manager.h"
#include "server_database_manager.h"

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

int parse_query(char* msg, char* pk, char* db_command, uint32_t* p_index)
{
    Timer t("parse_query");

    if(DEBUG) printf("Parsing message fields\n");

    char* token = strtok_r(msg, "|", &msg);
    int i = 0;
    while (token != NULL)
    {
        i++;
        token = strtok_r(NULL, "|", &msg);

        // Get client key
        if (i == 1) {
            memcpy(pk, token, 8);
            pk[8] = '\0';
            
            if(DEBUG) printf("pk: %s\n", pk);
        }

        // Get data index
        if (i == 3) {
            char* invalid_char;

            *p_index = (uint32_t)strtoul(token, &invalid_char, 10);

            if(*invalid_char != 0) {
                printf("\nInvalid query index message format.\n");
                return -1;
            }
           
            if(DEBUG) printf("disk_index: %u\n", *p_index); 
        }

        // Get data index
        if (i == 5) {
            strcpy(db_command, token);

            if(DEBUG) printf("command: %s\n", db_command);
        }
    }
    return 0;
}

int get_query_message(const Request& req, char* snd_msg, uint32_t* p_size)
{
    Timer t("get_query_message");

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

    strncpy(snd_msg, message_field.c_str(), (size_t)(*p_size));
    snd_msg[*p_size] = '\0';

    if(DEBUG) printf("Message: %s\n\n", snd_msg);

    return 0;
}

int enclave_get_response(stored_data_t stored, 
                         sgx_enclave_id_t global_eid, 
                         uint8_t* response, 
                         char* querier_pk, 
                         uint8_t* access_allowed)
{
    Timer t("enclave_get_response");

    // Get querier sealed key
    char seal_path[PATH_MAX_SIZE];
    sprintf(seal_path, "%s/%s", SEALS_PATH, querier_pk);

    size_t sealed_size = sizeof(sgx_sealed_data_t) + sizeof(uint8_t)*16;
    uint8_t* sealed_querier_key = (uint8_t*)malloc(sealed_size);

    if(DEBUG) printf("Reading key file from querier: %s\n", seal_path);

    FILE* seal_file = fopen(seal_path, "rb");
    if (seal_file == NULL) {
        printf("\nWarning: Failed to open the seal file \"%s\".\n", seal_path);
        free(sealed_querier_key);
        return -1;
    }
    else {
        fread(sealed_querier_key,1,sealed_size,seal_file);
        fclose(seal_file);
    }

    // Get storage sealed key
    sprintf(seal_path, "%s/storage_key", SEALS_PATH, stored.pk);
    seal_file = fopen(seal_path, "rb");
    uint8_t* sealed_storage_key = (uint8_t*)malloc(sealed_size);

    if(DEBUG) printf("Reading storage key file: %s\n");

    if (seal_file == NULL) {
        printf("\nWarning: Failed to open the seal file \"%s\".\n", seal_path);
        free(sealed_storage_key);
        return -1;
    }
    else {
        fread(sealed_storage_key,1,sealed_size,seal_file);
        fclose(seal_file);
    }

    //printf("%s\n", querier_pk);

    // Call enclave to unseal keys, decrypt with the publisher key and encrypt with querier key
    if(DEBUG) printf("Entering enclave\n");

    sgx_status_t ret;
    sgx_status_t ecall_status;
    ret =retrieve_data(global_eid, &ecall_status,
        (sgx_sealed_data_t*)sealed_querier_key,
        (sgx_sealed_data_t*)sealed_storage_key,
        stored.encrypted,
        stored.encrypted_size,
        querier_pk,
        response,
        access_allowed);

    if(DEBUG) printf("Exiting enclave\n");

    if(ret != SGX_SUCCESS || ecall_status != SGX_SUCCESS) {
        printf("\n(sec) Enclave problem inside retrieve_data:\n");
        if(ret == 0x5001)
            printf("Insuficient result buffer size (query).");
        else if(ret == 0x5002)
            printf("Access denied (query).");
        else
            printf("SGX error code %d, %d\n", (int)ret, (int)ecall_status);

        free(sealed_querier_key);
        free(sealed_storage_key);
        return -1;
    }

    free(sealed_querier_key);
    free(sealed_storage_key);
    return 0;
}

int get_response(stored_data_t stored, 
                 uint8_t* response, 
                 char* querier_pk, 
                 uint8_t* access_allowed)
{
    Timer t("get_response");

    // Get querier key
    char path[PATH_MAX_SIZE];
    sprintf(path, "%s/%s_i", SEALS_PATH, querier_pk);

    size_t size = sizeof(uint8_t)*16;
    uint8_t* querier_key = (uint8_t*)malloc(size);

    if(DEBUG) printf("Reading key file from querier: %s\n", path);

    FILE* file = fopen(path, "rb");
    if (file == NULL) {
        printf("\nWarning: Failed to open the seal file \"%s\".\n", path);
        free(querier_key);
        return -1;
    }
    else {
        fread(querier_key,1,size,file);
        fclose(file);
    }

    // Get storage key
    sprintf(path, "%s/storage_key_i", SEALS_PATH);
    file = fopen(path, "rb");
    uint8_t* storage_key = (uint8_t*)malloc(size);

    if(DEBUG) printf("Reading storage key file: %s\n", path);

    if (file == NULL) {
        printf("\nWarning: Failed to open the seal file \"%s\".\n", path);
        free(storage_key);
        return -1;
    }
    else {
        fread(storage_key,1,size,file);
        fclose(file);
    }

    //if(DEBUG) printf("Entering enclave\n");

    // Decrypt stored data
    if(DEBUG) printf("Decrypting data: ");

    uint32_t plain_data_size = MAX_DATA_SIZE;
    uint8_t* plain_data = (uint8_t*)malloc(plain_data_size*sizeof(uint8_t));
    sample_status_t ret;
    ret = decrypt_data(storage_key,
                       stored.encrypted,
                       stored.encrypted_size,
                       plain_data,
                       &plain_data_size);
    free(storage_key);
    if(ret != SAMPLE_SUCCESS) {
        printf("\n(ins) Error decrypting data for query\n");
        free(querier_key);
        free(plain_data);
        return -1;
    }
    plain_data[plain_data_size] = 0;
    if(DEBUG) printf("%s\n", plain_data);

    // Verify access permissions
    // Get permissions and verify if querier is included
    // pk|72d41281|type|123456|payload|250|permission1|72d41281
    char* text = (char*)malloc(1+plain_data_size*sizeof(char));
    memcpy(text, plain_data, plain_data_size);
    text[plain_data_size] = '\0';
    
    int permission_count = 0;
    *access_allowed = 0;

    int i = 0;
    char* token = strtok_r(text, "|", &text);
    while (token != NULL && *access_allowed == 0)
    {
        i++;
        token = strtok_r(NULL, "|", &text);
 
        if (i == 7+2*permission_count) {
            if(!memcmp(token, querier_pk, 8))
                *access_allowed = 1;
            permission_count++;
        }
    }

    // Encrypt data with querier key
    if(DEBUG) printf("Encrypting data");

    uint32_t response_size = stored.encrypted_size;
    if (*access_allowed) { 
        ret = encrypt_data(querier_key,
                           response,
                           &response_size,
                           plain_data,
                           plain_data_size);
    }
    free(querier_key);
    if(ret != SAMPLE_SUCCESS) {
        printf("\n(ins) Error encrypting data for query\n");
        free(plain_data);
        return -1;
    }
    free(plain_data);

    return 0;
}

void make_response(uint8_t* enc_data, uint32_t enc_data_size, char* response)
{
    Timer t("make_response");
    sprintf(response, "size|0x%02x|data|", enc_data_size);
    char auxiliar[7];
    for (uint32_t count=0; count<enc_data_size; count++)
    {
        sprintf(auxiliar, "%02x-", enc_data[count]);
        memcpy(&response[15+count*3], auxiliar, 3);
    }
    response[15+enc_data_size*3] = '\0';
    
    if(DEBUG) printf("Sending message: %s\n", response);
}

int server_query(bool secure, const Request& req, Response& res, sgx_enclave_id_t global_eid)
{
    Timer t("server_query");

    // Get message sent in HTTP header
    char* snd_msg = (char*)malloc(URL_MAX_SIZE*sizeof(char));

    uint32_t size;
    if(get_query_message(req, snd_msg, &size)) {
        free(snd_msg);
        return -1;
    }

    // Get data index and pk
    char pk[9];
    char db_command[MAX_DB_COMMAND_SIZE];
    uint32_t index;
    if(parse_query(snd_msg, pk, db_command, &index)) {
        free(snd_msg);
        return -1;
    }
    free(snd_msg);
    // printf("Index: %u\n", disk_index);

    // Thread open dedicated database connection 
    sqlite3 *db;

    if(DEBUG) printf("Opening dabase\n"); 

    if(sqlite3_open(DATABASE_PATH, &db)) {
       printf("Can't open database: %s\n", sqlite3_errmsg(db));
       return -1;
    } 

    // Create arrays for datas and datas sizes 
    char** datas = (char**)malloc(MAX_NUM_DATAS_QUERIED*sizeof(char*)); 
    uint32_t* datas_sizes = (uint32_t*)malloc(MAX_NUM_DATAS_QUERIED*sizeof(uint32_t)); 
    uint32_t filtered_data_count = 0;

    // Query data from db
    if(database_read(db, db_command, datas, datas_sizes, &filtered_data_count)) {
        free_data_array(datas, datas_sizes, filtered_data_count);
        sqlite3_close(db);
        return -1;
    }

    // Close connection to database
    sqlite3_close(db);

    // Get data at index
    if(index > filtered_data_count) {
        free_data_array(datas, datas_sizes, filtered_data_count);
        return -1;
    }

    char* data = (char*)malloc(MAX_DATA_SIZE*sizeof(char));
    memcpy(data, datas[index], datas_sizes[index]);
    free_data_array(datas, datas_sizes, filtered_data_count);

    // Separate parameters of stored data
    stored_data_t message; 
    if(get_stored_parameters(data, &message)) {
        free(data);
        return -1;
    }
    free(data);

    uint8_t *enc_data = (uint8_t*)malloc(message.encrypted_size*sizeof(char));
    char *response = (char*)malloc((15+3*message.encrypted_size+1)*sizeof(char));

    uint8_t access_allowed;
    if (secure == true) {
        if(enclave_get_response(message, global_eid, enc_data, pk, &access_allowed)) {
            free(enc_data);
            free(response);
            return -1;
        }
    } 

    else {
        if(get_response(message, enc_data, pk, &access_allowed)) {
            free(enc_data);
            free(response);
            return -1;
        }
    }

    if (!access_allowed) {
        if(DEBUG) printf("\nAccess denied\n");
        res.set_content("Denied", "text/plain");
    } 
    else {
        if(DEBUG) printf("\nAccess accepted\n");
        make_response(enc_data, message.encrypted_size, response);
        res.set_content(response, "text/plain");
    }
    
    free(response);
    free(enc_data);
    free(message.encrypted);

    return 0; 
}