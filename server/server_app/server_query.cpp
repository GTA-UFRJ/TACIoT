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

server_error_t parse_query(char* msg, access_message_t* p_rcv_msg)
{
    Timer t("parse_query");
    if(DEBUG_PRINT) printf("\nParsing query message fields\n");

    if(DEBUG_PRINT) printf("Parsing message fields\n");

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

            if(DEBUG_PRINT) printf("pk: %s\n", p_rcv_msg->pk);
        }

        // Get data index
        if (i == 3) {

            p_rcv_msg->index = (uint32_t)strtoul(token, &invalid_char, 10);

            if(*invalid_char != 0) 
                return print_error_message(INVALID_INDEX_FIELD_ERROR);
           
            if(DEBUG_PRINT) printf("index: %u\n", p_rcv_msg->index); 
        }
        // Get command size
        if (i == 5) {
            p_rcv_msg->command_size = (uint32_t)strtoul(token, &invalid_char, 16);

            if(*invalid_char != 0) {
                printf("\nInvalid command size message format.\n");
                return INVALID_COMMAND_SIZE_FIELD_ERROR;
            }

            if(DEBUG_PRINT) printf("command_size: %u\n", p_rcv_msg->command_size);
        }

        // Get command 
        if (i == 7) { 

            p_rcv_msg->command = (char*)malloc(1+p_rcv_msg->command_size);
            memcpy(p_rcv_msg->command, token, p_rcv_msg->command_size);
            p_rcv_msg->command[p_rcv_msg->command_size] = 0;

            if(DEBUG_PRINT) printf("command: %s\n", p_rcv_msg->command);
        }
        
        // Get encrypted 
        if (i == 9) {

            if(DEBUG_PRINT) printf("encrypted pk: ");

            for (uint32_t j=0; j<8+12+16; j++){
                auxiliar[0] = token[3*j];
                auxiliar[1] = token[3*j+1];
                auxiliar[2] = '\0';
                p_rcv_msg->encrypted[j] = (uint8_t)strtoul(auxiliar, &invalid_char, 16);

                if(auxiliar != 0 && *invalid_char != 0) {
                    free(p_rcv_msg->encrypted);
                    return print_error_message(INVALID_ENCRYPTED_FIELD_ERROR);
                }

                if(DEBUG_PRINT) printf("%02x,", (unsigned)p_rcv_msg->encrypted[j]);
            }
            p_rcv_msg->encrypted[8+12+16] = '\0';
            if(DEBUG_PRINT) printf("\n");
        }
    }
    return OK;
}

server_error_t get_query_message(const Request& req, char* snd_msg, uint32_t* p_size)
{
    Timer t("get_query_message");
    if(DEBUG_PRINT) printf("\nGetting query message fields:\n");

    std::string size_field = req.matches[1].str();

    try {
        *p_size = (uint32_t)std::stoul(size_field);
    }
    catch (std::invalid_argument& exception) {
        return print_error_message(INVALID_HTTP_MESSAGE_SIZE_FIELD_ERROR);
    }

    if(*p_size > URL_MAX_SIZE)
        return print_error_message(HTTP_MESSAGE_SIZE_OVERFLOW_ERROR);

    if(DEBUG_PRINT) printf("Size: %u\n", *p_size);

    std::string message_field = req.matches[2].str();

    strncpy(snd_msg, message_field.c_str(), (size_t)(*p_size-1));
    snd_msg[*p_size] = '\0';

    if(DEBUG_PRINT) printf("Message: %s\n\n", snd_msg);

    return OK;
}

server_error_t enclave_get_response(stored_data_t stored, 
                         sgx_enclave_id_t global_eid, 
                         uint8_t* response, 
                         access_message_t rcv_msg, 
                         uint8_t* access_allowed)
{
    *access_allowed = 0;

    Timer t("enclave_get_response");

    // Search user file and read sealed key
    char* querier_seal_path = (char*)malloc(PATH_MAX_SIZE);
    sprintf(querier_seal_path, "%s/%s", SEALS_PATH, rcv_msg.pk);

    if(DEBUG_PRINT) printf("\nReading querier key file: %s\n", querier_seal_path);

    FILE* querier_seal_file = fopen(querier_seal_path, "rb");
    free(querier_seal_path);
    if (querier_seal_file == NULL) 
        return print_error_message(OPEN_CLIENT_KEY_FILE_ERROR);
    
    size_t querier_sealed_size = sizeof(sgx_sealed_data_t) + sizeof(uint8_t)*16;
    uint8_t* querier_sealed_data = (uint8_t*)malloc(querier_sealed_size);
    fread(querier_sealed_data,1,querier_sealed_size,querier_seal_file);
    fclose(querier_seal_file);


    // Search server file and read sealed key
    char* storage_seal_path = (char*)malloc(PATH_MAX_SIZE);
    sprintf(storage_seal_path, "%s/storage_key", SEALS_PATH);

    if(DEBUG_PRINT) printf("\nReading storage key file: %s\n", storage_seal_path);

    FILE* storage_seal_file = fopen(storage_seal_path, "rb");
    free(storage_seal_path);
    if (storage_seal_file == NULL) {
        free(querier_sealed_data);     
        return print_error_message(OPEN_SERVER_KEY_FILE_ERROR);
    }

    size_t storage_sealed_size = sizeof(sgx_sealed_data_t) + sizeof(uint8_t)*16;
    uint8_t* storage_sealed_data = (uint8_t*)malloc(storage_sealed_size);
    fread(storage_sealed_data,1,storage_sealed_size,storage_seal_file);
    fclose(storage_seal_file);

    //printf("%s\n", querier_pk);


    // Call enclave to unseal keys, decrypt with the querier key and encrypt with querier key
    {
    Timer t2("retrieve_data");

    if(DEBUG_PRINT) printf("\nEntering enclave to verify access permissions\n");

    sgx_status_t ret;
    sgx_status_t ecall_status;
    ret =retrieve_data(global_eid, &ecall_status,
        (sgx_sealed_data_t*)querier_sealed_data,
        (sgx_sealed_data_t*)storage_sealed_data,
        rcv_msg.encrypted,
        stored.encrypted,
        stored.encrypted_size,
        rcv_msg.pk,
        response,
        access_allowed);
    if(DEBUG_PRINT) printf("Exiting enclave\n");

    free(querier_sealed_data);
    free(storage_sealed_data);

    if(ret != SGX_SUCCESS || ecall_status != SGX_SUCCESS) {
        
        if(ret == 0x5001) printf("Insuficient result buffer size (query).");
        else if(ret == 0x5002) printf("Access denied (query).");
        else printf("SGX error code 0x%04x, 0x%04x\n", (int)ret, (int)ecall_status);
        return print_error_message(RETRIEVE_DATA_ENCLAVE_ERROR);
    }
    }
    return (*access_allowed ? OK : ACCESS_DENIED);;
}

server_error_t get_response(stored_data_t stored, 
                 uint8_t* response, 
                 access_message_t rcv_msg, 
                 uint8_t* access_allowed)
{
    *access_allowed = 0;

    Timer t("get_response");

    // Search user file and read key
    char* querier_key_path = (char*)malloc(PATH_MAX_SIZE);
    sprintf(querier_key_path, "%s/%s_i", SEALS_PATH, rcv_msg.pk);

    if(DEBUG_PRINT) printf("\nReading querier key file: %s\n", querier_key_path);

    FILE* querier_key_file = fopen(querier_key_path, "rb");
    free(querier_key_path);
    if (querier_key_file == NULL) 
        return print_error_message(OPEN_CLIENT_KEY_FILE_ERROR);

    size_t querier_key_size = 16;
    uint8_t* querier_key = (uint8_t*)malloc(querier_key_size);
    fread(querier_key,1,querier_key_size,querier_key_file);
    fclose(querier_key_file);


    // Decrypt pk 
    if(DEBUG_PRINT) printf("\nDecrypting pk\n");

    uint32_t recovered_pk_size = 8;
    uint8_t* recovered_pk = (uint8_t*)malloc(1+recovered_pk_size*sizeof(uint8_t));
    sample_status_t encryption_ret;
    encryption_ret = decrypt_data(querier_key,
                       rcv_msg.encrypted,
                       8+12+16,
                       recovered_pk,
                       &recovered_pk_size);
    if(encryption_ret != SAMPLE_SUCCESS) {
        free(recovered_pk);
        return print_error_message(MESSAGE_DECRYPTION_ERROR);
    }
    recovered_pk[recovered_pk_size] = 0;
    if(DEBUG_PRINT) printf("Recovered pk: %s\n", recovered_pk);


    // Verify if pks are equals
    int different_keys = strcmp(rcv_msg.pk, (char*)recovered_pk); 
    free(recovered_pk);
    if(different_keys) return print_error_message(AUTHENTICATION_ERROR);


    // Search server file and read storage key
    char* storage_key_path = (char*)malloc(PATH_MAX_SIZE);
    sprintf(storage_key_path, "%s/storage_key_i", SEALS_PATH);

    if(DEBUG_PRINT) printf("\nReading storage key file: %s\n", storage_key_path);

    FILE* storage_key_file = fopen(storage_key_path, "rb");
    free(storage_key_path);
    if (storage_key_file == NULL) {
        free(querier_key);
        return print_error_message(OPEN_SERVER_KEY_FILE_ERROR);
    }

    size_t storage_key_size = 16;
    uint8_t* storage_key = (uint8_t*)malloc(storage_key_size);
    fread(storage_key,1,storage_key_size,storage_key_file);
    fclose(storage_key_file);
    

    // Decrypt stored data
    if(DEBUG_PRINT) printf("\nDecrypting stored data\n");

    uint32_t plain_data_size = MAX_DATA_SIZE;
    uint8_t* plain_data = (uint8_t*)malloc(plain_data_size*sizeof(uint8_t));
    encryption_ret = decrypt_data(storage_key,
                       stored.encrypted,
                       stored.encrypted_size,
                       plain_data,
                       &plain_data_size);
    free(storage_key);
    if(encryption_ret != SAMPLE_SUCCESS) {
        free(querier_key);
        free(plain_data);
        return print_error_message(DATA_DECRYPTION_ERROR);
    }
    plain_data[plain_data_size] = 0;
    if(DEBUG_PRINT) printf("%s\n", plain_data);


    // Verify access permissions
    if(DEBUG_PRINT) printf("\nVerifying access permissions\n");
    
    // pk|72d41281|type|123456|payload|250|permission1|72d41281
    char* text = (char*)malloc(1+plain_data_size);
    memcpy(text, plain_data, plain_data_size);
    text[plain_data_size] = '\0';
    
    int permission_count = 0;
    *access_allowed = 0;

    int i = 0;
    char* auxiliar_text = text;
    char* token = strtok_r(auxiliar_text, "|", &auxiliar_text);
    while (token != NULL && *access_allowed == 0)
    {
        i++;
        token = strtok_r(NULL, "|", &auxiliar_text);
 
        if (i == 7+2*permission_count) {
            if(!memcmp(token, rcv_msg.pk, 8))
                *access_allowed = 1;
            permission_count++;
        }
    }
    free(text);

    // Encrypt data with querier key
    if(DEBUG_PRINT) printf("\nEncrypting data with querier pk\n");

    uint32_t response_size = stored.encrypted_size;
    if (*access_allowed) { 
        encryption_ret = encrypt_data(querier_key,
                           response,
                           &response_size,
                           plain_data,
                           plain_data_size);
    }
    free(querier_key);
    free(plain_data);
    if(encryption_ret != SAMPLE_SUCCESS)
        return print_error_message(MESSAGE_ENCRYPTION_ERROR);

    return (*access_allowed ? OK : ACCESS_DENIED);
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
    
    if(DEBUG_PRINT) printf("Sending message: %s\n", response);
}

server_error_t server_query(bool secure, const Request& req, Response& res, sgx_enclave_id_t global_eid)
{
    Timer t("server_query");
    server_error_t ret = OK;

    // Get message sent in HTTP header
    char* snd_msg = (char*)malloc(URL_MAX_SIZE);

    uint32_t size;
    ret = get_query_message(req, snd_msg, &size);
    if(ret) {
        free(snd_msg);
        return ret;
    }

    // Get data index and pk
    access_message_t rcv_msg;
    ret = parse_query(snd_msg, &rcv_msg);
    free(snd_msg);
    if(ret) return ret;

    // Thread open dedicated database connection 
    sqlite3 *db;

    if(DEBUG_PRINT) printf("\nOpening dabase\n"); 

    if(sqlite3_open(DATABASE_PATH, &db)) {
       printf("SQL error: %s\n", sqlite3_errmsg(db));
       return OPEN_DATABASE_ERROR;
    } 

    // Create arrays for datas and datas sizes 
    char** datas = (char**)malloc(MAX_NUM_DATAS_QUERIED*sizeof(char*)); 
    uint32_t* datas_sizes = (uint32_t*)malloc(MAX_NUM_DATAS_QUERIED*sizeof(uint32_t)); 
    uint32_t filtered_data_count = 0;

    // Query data from db
    ret = database_read(db, rcv_msg.command, datas, datas_sizes, &filtered_data_count);
    if(ret) {
        free_data_array(datas, datas_sizes, filtered_data_count);
        sqlite3_close(db);
        return DB_SELECT_EXECUTION_ERROR;
    }
    sqlite3_close(db);

    // Get data at index
    if(rcv_msg.index >= filtered_data_count) {
        free_data_array(datas, datas_sizes, filtered_data_count);
        return print_error_message(OUT_OF_BOUND_INDEX);
    }

    char* data = (char*)malloc(MAX_DATA_SIZE);
    memcpy(data, datas[rcv_msg.index], datas_sizes[rcv_msg.index]);
    free_data_array(datas, datas_sizes, filtered_data_count);

    // Separate parameters of stored data
    stored_data_t message; 
    ret = get_stored_parameters(data, &message);
    free(data);
    if(ret) return ret;

    // Verify access permissions
    uint8_t *enc_data = (uint8_t*)malloc(message.encrypted_size);
    char *response = (char*)malloc(15+3*message.encrypted_size+1);

    uint8_t access_allowed;
    if (secure == true)
        ret = enclave_get_response(message, global_eid, enc_data, rcv_msg, &access_allowed);
    else 
        ret = get_response(message, enc_data, rcv_msg, &access_allowed);

    if(!ret) {
        if(DEBUG_PRINT) printf("\nAccess accepted\n");
        make_response(enc_data, message.encrypted_size, response);
        res.set_content(response, "text/plain");
    }
    free(response);
    free(enc_data);
    free(message.encrypted);

    return ret; 
}