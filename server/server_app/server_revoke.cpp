/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Descripton: remove data
 */

#include <cstdio>
#include <stdlib.h>
#include <iostream>
#include <string.h>
#include <stdio.h> 
#include <chrono>
#include <thread>
#include "timer.h"

#include "server_revoke.h"
#include "server_disk_manager.h"
#include "server_database_manager.h"

#include "sample_libcrypto.h"   // sample_aes_gcm_128bit_key_t
#include "config_macros.h"      // ULTRALIGH_SAMPLE
#include "utils_sgx.h"
#include "utils.h"
#include "encryption.h"
#include HTTPLIB_PATH
#include "server_enclave_u.h"
//#include "ecp.h"                // sample_ec_key_128bit_t

#include "sgx_urts.h"
#include "sgx_eid.h"
#include "sgx_ukey_exchange.h"
#include "sgx_uae_epid.h"
#include "sgx_uae_quote_ex.h"
#include "sgx_tcrypto.h"

using namespace httplib;


// pk|72d41281|type|123456|size|62|encrypted|...
server_error_t parse_revocation(char* msg, access_message_t* p_rcv_msg)
{
    Timer t("parse_revokation");
    
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

        // Get data index
        if (i == 3) {

            p_rcv_msg->index = (uint32_t)strtoul(token, &invalid_char, 10);

            if(*invalid_char != 0) {
                printf("\nInvalid query index message format.\n");
                return INVALID_INDEX_FIELD_ERROR;
            }
           
            if(DEBUG) printf("index: %u\n", p_rcv_msg->index); 
        }
        // Get command size
        if (i == 5) {
            p_rcv_msg->command_size = (uint32_t)strtoul(token, &invalid_char, 16);

            if(*invalid_char != 0) {
                printf("\nInvalid command size message format.\n");
                return INVALID_COMMAND_SIZE_FIELD_ERROR;
            }

            if(DEBUG) printf("command_size: %u\n", p_rcv_msg->command_size);
        }

        // Get command 
        if (i == 7) { 

            p_rcv_msg->command = (char*)malloc(1+p_rcv_msg->command_size);
            memcpy(p_rcv_msg->command, token, p_rcv_msg->command_size);
            p_rcv_msg->command[p_rcv_msg->command_size] = 0;

            if(DEBUG) printf("command: %s\n", p_rcv_msg->command);
        }
        
        // Get encrypted 
        if (i == 9) {

            if(DEBUG) printf("encrypted pk: ");

            for (uint32_t j=0; j<8+12+16; j++){
                auxiliar[0] = token[3*j];
                auxiliar[1] = token[3*j+1];
                auxiliar[2] = '\0';
                p_rcv_msg->encrypted[j] = (uint8_t)strtoul(auxiliar, &invalid_char, 16);

                if(auxiliar != 0 && *invalid_char != 0) {
                    printf("\nInvalid encrypted revocation message format.\n");
                    free(p_rcv_msg->encrypted);
                    return INVALID_ENCRYPTED_FIELD_ERROR;
                }

                if(DEBUG) printf("%02x,", (unsigned)p_rcv_msg->encrypted[j]);
            }
            p_rcv_msg->encrypted[8+12+16] = '\0';
            if(DEBUG) printf("\n");
        }
    }

    return OK;
}

server_error_t get_revocation_message(const Request& req, char* snd_msg, uint32_t* p_size)
{
    Timer t("get_revocation_message");

    std::string size_field = req.matches[1].str();

    try {
        *p_size = (uint32_t)std::stoul(size_field);
    }
    catch (std::invalid_argument& exception) {
        printf("\nFailed to detect HTTP message size\n");
        return INVALID_HTTP_MESSAGE_SIZE_FIELD_ERROR;
    }

    if(*p_size > URL_MAX_SIZE) {
        printf("\nHTTP message bigger than the maximum size\n");
        return HTTP_MESSAGE_SIZE_OVERFLOW_ERROR;
    }

    if(DEBUG) printf("Size: %u\n", *p_size);

    std::string message_field = req.matches[2].str();

    strncpy(snd_msg, message_field.c_str(), (size_t)(*p_size-1));
    snd_msg[*p_size] = '\0';
    
    if(DEBUG) printf("Message: %s\n\n", snd_msg);

    return OK;
}

server_error_t enclave_verify_deletion(stored_data_t stored, 
                            sgx_enclave_id_t global_eid, 
                            access_message_t rcv_msg, 
                            uint8_t* access_allowed) 
{
    *access_allowed = 0;

    Timer t("enclave_verify_deletion");

    char seal_path[PATH_MAX_SIZE];
    size_t sealed_size = sizeof(sgx_sealed_data_t) + sizeof(uint8_t)*16;

    // Get revoker sealed key
    sprintf(seal_path, "%s/%s", SEALS_PATH, rcv_msg.pk);
    uint8_t* sealed_revoker_key = (uint8_t*)malloc(sealed_size);

    if(DEBUG) printf("Reading revoker key file: %s\n", seal_path);

    FILE* seal_file = fopen(seal_path, "rb");
    if (seal_file == NULL) {
        printf("\nWarning: Failed to open the seal file \"%s\".\n", seal_path);
        free(sealed_revoker_key);
        return OPEN_CLIENT_KEY_FILE_ERROR;
    }
    else {
        fread(sealed_revoker_key,1,sealed_size,seal_file);
        fclose(seal_file);
    }

    // Get storage sealed key
    sprintf(seal_path, "%s/storage_key", SEALS_PATH);
    uint8_t* sealed_storage_key = (uint8_t*)malloc(sealed_size);

    if(DEBUG) printf("Reading storage key file: %s\n", seal_path);

    seal_file = fopen(seal_path, "rb");
    if (seal_file == NULL) {
        printf("\nWarning: Failed to open the seal file \"%s\".\n", seal_path);
        free(sealed_storage_key);
        return OPEN_SERVER_KEY_FILE_ERROR;
    }
    else {
        fread(sealed_storage_key,1,sealed_size,seal_file);
        fclose(seal_file);
    }

    //printf("%s\n", querier_pk);

    // Call enclave to decrypt pk and stored data 
    {
    Timer t2("revoke_data");
    if(DEBUG) printf("Entering enclave\n");

    sgx_status_t ret;
    sgx_status_t ecall_status;
    ret =revoke_data(global_eid, &ecall_status,
        (sgx_sealed_data_t*)sealed_revoker_key,
        (sgx_sealed_data_t*)sealed_storage_key,
        rcv_msg.encrypted,
        stored.encrypted,
        stored.encrypted_size,
        rcv_msg.pk,
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

        free(sealed_storage_key);
        return REVOKE_DATA_ENCLAVE_ERROR;
    }
    }
    free(sealed_storage_key);
    return OK;
}


server_error_t verify_deletion(stored_data_t stored, access_message_t rcv_msg, uint8_t* access_allowed) 
{
    *access_allowed = 0;

    Timer t("verify_deletion");

    char path[PATH_MAX_SIZE];
    size_t size = sizeof(uint8_t)*16;

    // Get revoker key
    sprintf(path, "%s/%s_i", SEALS_PATH, rcv_msg.pk);
    uint8_t* revoker_key = (uint8_t*)malloc(size);

    if(DEBUG) printf("Reading revoker key file: %s\n", path);

    FILE* file = fopen(path, "rb");
    if (file == NULL) {
        printf("\nWarning: Failed to open the seal file \"%s\".\n", path);
        free(revoker_key);
        return OPEN_CLIENT_KEY_FILE_ERROR;
    }
    else {
        fread(revoker_key,1,size,file);
        fclose(file);
    }

    // Decrypt pk 
    if(DEBUG) printf("Decrypting pk: ");

    uint32_t recovered_pk_size = 8;
    uint8_t* recovered_pk = (uint8_t*)malloc(1+recovered_pk_size*sizeof(uint8_t));
    sample_status_t encryption_ret;
    encryption_ret = decrypt_data(revoker_key,
                       rcv_msg.encrypted,
                       8+12+16,
                       recovered_pk,
                       &recovered_pk_size);
    free(revoker_key);
    if(encryption_ret != SAMPLE_SUCCESS) {
        printf("\n(ins) Error decrypting data for query\n");
        free(recovered_pk);
        return MESSAGE_DECRYPTION_ERROR;
    }
    recovered_pk[recovered_pk_size] = 0;
    if(DEBUG) printf("%s\n", recovered_pk);

    // Verify if pks are equals
    if(strcmp(rcv_msg.pk, (char*)recovered_pk)){
        printf("\n(ins) Invalid encrypted pk. Could not authenticate client\n");
        free(recovered_pk);
        return AUTHENTICATION_ERROR;
    }
    free(recovered_pk);

    // Verify if nonce is fresh
    // verify_nonce(revoker_key, rcv_msg.encrypted+16);

    // Get storage key
    sprintf(path, "%s/storage_key_i", SEALS_PATH);
    uint8_t* storage_key = (uint8_t*)malloc(size);

    if(DEBUG) printf("Reading storage key file: %s\n", path);

    file = fopen(path, "rb");
    if (file == NULL) {
        printf("\nWarning: Failed to open the seal file \"%s\".\n", path);
        free(storage_key);
        return OPEN_SERVER_KEY_FILE_ERROR;
    }
    else {
        fread(storage_key,1,size,file);
        fclose(file);
    }

    // Decrypt stored data
    if(DEBUG) printf("Decrypting data: ");

    uint32_t plain_data_size = MAX_DATA_SIZE;
    uint8_t* plain_data = (uint8_t*)malloc(1+plain_data_size*sizeof(uint8_t));
    encryption_ret = decrypt_data(storage_key,
                       stored.encrypted,
                       stored.encrypted_size,
                       plain_data,
                       &plain_data_size);
    free(storage_key);
    if(encryption_ret != SAMPLE_SUCCESS) {
        printf("\n(ins) Error decrypting data for query\n");
        free(plain_data);
        return DATA_DECRYPTION_ERROR;
    }
    plain_data[plain_data_size] = 0;
    if(DEBUG) printf("%s\n", plain_data);

    // Verify if client is the owner of the data
    if(strncmp((char*)plain_data+3, rcv_msg.pk, 8)) {
        printf("\n(ins) Client does not own this data\n");
        free(plain_data);
        return OWNERSHIP_VIOLATION_ERROR;
    }
    free(plain_data);

    // Allow deletion
    *access_allowed = 1;

    return OK;
}

server_error_t server_revoke(bool secure, const Request& req, Response& res, sgx_enclave_id_t global_eid)
{
    Timer t("server_revoke");
    server_error_t ret = OK;

    // Get message sent in HTTP header
    char* snd_msg = (char*)malloc(URL_MAX_SIZE*sizeof(char));

    uint32_t size;
    if((ret = get_revocation_message(req, snd_msg, &size))) {
        free(snd_msg);
        return ret;
    }

    // Server receives and separate parameters according to protocol
    access_message_t rcv_msg;
    if((ret = parse_revocation(snd_msg, &rcv_msg)))
        return ret;
    free(snd_msg);

    // Thread open dedicated database connection 
    sqlite3 *db;

    if(DEBUG) printf("Opening dabase\n"); 

    if(sqlite3_open(DATABASE_PATH, &db)) {
       printf("Can't open database: %s\n", sqlite3_errmsg(db));
       return OPEN_DATABASE_ERROR;
    }

    // Create arrays for datas and datas sizes 
    char** datas = (char**)malloc(MAX_NUM_DATAS_QUERIED*sizeof(char*)); 
    uint32_t* datas_sizes = (uint32_t*)malloc(MAX_NUM_DATAS_QUERIED*sizeof(uint32_t)); 
    uint32_t filtered_data_count = 0;

    // Query data from db
    if((ret = database_read(db, rcv_msg.command, datas, datas_sizes, &filtered_data_count))) {
        free_data_array(datas, datas_sizes, filtered_data_count);
        sqlite3_close(db);
        return ret;
    }

    // Close connection to database
    sqlite3_close(db);

    // Get data at index
    if(rcv_msg.index > filtered_data_count) {
        free_data_array(datas, datas_sizes, filtered_data_count);
        return OUT_OF_BOUND_INDEX;
    }

    char* data = (char*)malloc(MAX_DATA_SIZE*sizeof(char));
    memcpy(data, datas[rcv_msg.index], datas_sizes[rcv_msg.index]);
    free_data_array(datas, datas_sizes, filtered_data_count);

    // Separate parameters of stored data
    stored_data_t message; 
    if((ret = get_stored_parameters(data, &message))) {
        free(data);
        return ret;
    }
    free(data);

    uint8_t access_allowed = 0;
    if (secure == true) {
        if((ret = enclave_verify_deletion(message, global_eid, rcv_msg, &access_allowed))) 
            return ret;
    } 

    else {
        if((ret = verify_deletion(message, rcv_msg, &access_allowed))) 
            return ret;
    }

    if (!access_allowed) {
        if(DEBUG) printf("\nAccess denied\n");
        free(message.encrypted);
        return ret;
    } 
    else {
        if(DEBUG) printf("\nAccess accepted\n");
        if((ret = database_delete(db, message))){
            free(message.encrypted);
            return ret;
        }
        res.set_content("Accepted", "text/plain");
    }
    free(message.encrypted);

    return OK; 
}