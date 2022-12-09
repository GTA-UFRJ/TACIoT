/*
 * Grupo de Teleinformatica e Automacao (GTA, Coppe, UFRJ)
 * Autor: Guilherme Araujo Thomaz
 * Data da ultima modificacao: 23/12/2021
 * Descricao: funcoes do enclave do servidor
 * 
 * Este codigo foi modificado seguindo as permissoes da licenca
 * da Intel Corporation, apresentadas a seguir
 *
 */
/*
 * Copyright (C) 2011-2020 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <assert.h>
#include "server_enclave_t.h"
#include "sgx_tkey_exchange.h"
#include "sgx_tcrypto.h"
#include "sgx_tseal.h"
#include "sgx_trts.h"
//#include "server_processing.h"
#include <string.h>
#include <string>
#include <stdlib.h>

uint8_t g_secret[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

// Process data before publishing
sgx_status_t process_data(
    sgx_sealed_data_t* publisher_sealed_key,
    sgx_sealed_data_t* storage_sealed_key,
    char* pk,
    uint8_t* encrypted_data,
    uint32_t encrypted_data_size,
    uint8_t*  processed_result,
    uint32_t buffer_max_size,
    uint32_t* processed_result_size)
{
    sgx_status_t ret = SGX_SUCCESS;

    // Unseal keys
    uint8_t publisher_key[16] = {0}; 
    uint32_t publisher_key_size = 16;
    ret = sgx_unseal_data(publisher_sealed_key, NULL, NULL, &publisher_key[0], &publisher_key_size);
    /*
    if(ret != SGX_SUCCESS) {
        uint8_t error = (uint8_t)ret;
        ocall_print_secret(&error, 1);
        return ret;
    }*/

    // Unseal keys
    uint8_t storage_key[16] = {0}; 
    uint32_t storage_key_size = 16;
    ret = sgx_unseal_data(storage_sealed_key, NULL, NULL, &storage_key[0], &storage_key_size);
    /*
    if(ret != SGX_SUCCESS) {
        uint8_t error = (uint8_t)ret;
        ocall_print_secret(&error, 1);
        return ret;
    }*/

    sgx_aes_gcm_128bit_key_t my_key;
    memcpy(my_key, publisher_key, (size_t)publisher_key_size);
    //ocall_print_secret(&key[0], 16);

    sgx_aes_gcm_128bit_key_t server_key;
    memcpy(server_key, storage_key, (size_t)storage_key_size);
    //ocall_print_secret(&key[0], 16);

    /* 
    * Decrypt data using key
    *
    * Encrypted data:      | MAC | IV | AES128(data)
    * Buffer size:           16    12   size(data)
    *
    * MAC reference:         &data       :   &data+16
    * IV reference:          &data+16    :   &data+16+12
    * AES128(data) ref:      &data+12+16 : 
    */
    uint32_t dec_msg_len = encrypted_data_size - 16 - 12;
    uint8_t decMessage [dec_msg_len];
    memset(decMessage, 0, dec_msg_len);
   
    ret = sgx_rijndael128GCM_decrypt(&my_key,
                                    &encrypted_data[0] + 16 + 12,
                                    dec_msg_len,
                                    &decMessage[0],
                                    &encrypted_data[0] + 16,
                                    12,
                                    NULL,
                                    0,
                                    (const sgx_aes_gcm_128bit_tag_t*)
                                    (&encrypted_data[0]));
   // ocall_print_secret(&decMessage[0], dec_msg_len);
    if(ret != SGX_SUCCESS) {
        return ret;
    }

    // Verify if pks are equals
    if(memcmp(pk, decMessage+3, 8)){
        ret = (sgx_status_t)0x5001;
        return ret;
    }
    
    // Encrypt data using key
    *processed_result_size = 16 + 12 + dec_msg_len;
    if(*processed_result_size > buffer_max_size) {
        ret = (sgx_status_t)0x5001;
        return ret;
    }

    uint8_t aes_gcm_iv[12] = {0};
    memcpy(processed_result+16, aes_gcm_iv, 12);
    ret = sgx_rijndael128GCM_encrypt(&server_key,
                                    decMessage,
                                    dec_msg_len,
                                    processed_result + 16 + 12,
                                    &aes_gcm_iv[0],
                                    12,
                                    NULL,
                                    0,
                                    (sgx_aes_gcm_128bit_tag_t*)
                                    (processed_result));
    //ocall_print_secret(&processed_result[0], *processed_result_size);
    if(ret != SGX_SUCCESS) {
        return ret;
    }

    processed_result[*processed_result_size] = 0;
    return SGX_SUCCESS;
}

sgx_status_t retrieve_data(
    sgx_sealed_data_t* sealed_querier_key,
    sgx_sealed_data_t* sealed_storage_key,
    uint8_t* encrypted_pk,
    uint8_t* encrypted_data,
    uint32_t encrypted_data_size,
    char* querier_pk,
    uint8_t* result,
    uint8_t* accepted)
{
    // Verify if nonce is fresh
    // TODO

    *accepted = 0;

    sgx_status_t ret = SGX_SUCCESS;

    // Unseal keys
    uint32_t key_size = 16;

    uint8_t querier_key[16] = {0}; 
    ret = sgx_unseal_data(sealed_querier_key, NULL, NULL, &querier_key[0], &key_size);
    /*if(ret != SGX_SUCCESS) {
        uint8_t error = (uint8_t)ret;
        ocall_print_secret(&error, 1);
        return ret;
    }*/

    uint8_t storage_key[16] = {0}; 
    ret = sgx_unseal_data(sealed_storage_key, NULL, NULL, &storage_key[0], &key_size);
    /*if(ret != SGX_SUCCESS) {
        uint8_t error = (uint8_t)ret;
        ocall_print_secret(&error, 1);
        return ret;
    }*/

    sgx_aes_gcm_128bit_key_t my_key;
    memcpy(my_key, querier_key, (size_t)key_size);
    
    sgx_aes_gcm_128bit_key_t server_key;
    memcpy(server_key, storage_key, (size_t)key_size);

    /* 
    * Decrypt pk
    *
    * Encrypted data:      | MAC | IV | AES128(data)
    * Buffer size:           16    12   size(data)
    *
    * MAC reference:         &data       :   &data+16
    * IV reference:          &data+16    :   &data+16+12
    * AES128(data) ref:      &data+12+16 : 
    */
    uint32_t dec_pk_size = 8; 
    uint8_t dec_pk [dec_pk_size+1];
    memset(dec_pk,0,dec_pk_size+1);;
    ret = sgx_rijndael128GCM_decrypt(&my_key,
                                    &encrypted_pk[0] + 16 + 12,
                                    dec_pk_size,
                                    &dec_pk[0],
                                    &encrypted_pk[0] + 16,
                                    12,
                                    NULL,
                                    0,
                                    (const sgx_aes_gcm_128bit_tag_t*)
                                    (&encrypted_pk[0]));
    if(ret != SGX_SUCCESS) {
        return ret;
    }

    // Verify if pks are equals
    if(memcmp(querier_pk, dec_pk, 8)){
        ret = (sgx_status_t)0x5001;
        return ret;
    }

    /* 
    * Decrypt data received from DB/disk copy
    *
    * Encrypted data:      | MAC | IV | AES128(data)
    * Buffer size:           16    12   size(data)
    *
    * MAC reference:         &data       :   &data+16
    * IV reference:          &data+16    :   &data+16+12
    * AES128(data) ref:      &data+12+16 : 
    */
    uint32_t dec_msg_len = encrypted_data_size-12-16; 
    uint8_t decMessage [dec_msg_len];
    memset(decMessage,0,dec_msg_len);;
    ret = sgx_rijndael128GCM_decrypt(&server_key,
                                    &encrypted_data[0] + 16 + 12,
                                    dec_msg_len,
                                    &decMessage[0],
                                    &encrypted_data[0] + 16,
                                    12,
                                    NULL,
                                    0,
                                    (const sgx_aes_gcm_128bit_tag_t*)
                                    (&encrypted_data[0]));
    if(ret != SGX_SUCCESS) {
        return ret;
    }

    // Get permissions and verify if querier is included
    // pk|72d41281|type|123456|payload|250|permission1|72d41281
    char* text = (char*)malloc(1+(size_t)dec_msg_len);
    memcpy(text, decMessage, dec_msg_len);
    text[dec_msg_len] = '\0';
    
    int permission_count = 0;
    *accepted = 0;

    int i = 0;
    char* token = strtok_r(text, "|", &text);
    while (token != NULL && *accepted == 0)
    {
        i++;
        token = strtok_r(NULL, "|", &text);
 
        if (i == 7+2*permission_count) {
            if(!memcmp(token, querier_pk, 8))
                *accepted = 1;
            permission_count++;
        }
    }

    // Allows automatic access for benchmarking 
    // *accepted = 1; 

    // Encrypt data with querier key
    if (*accepted){
        uint8_t aes_gcm_iv[12] = {0};
        memcpy(result+16, aes_gcm_iv, 12);
        ret = sgx_rijndael128GCM_encrypt(&my_key,
                                        &decMessage[0],
                                        dec_msg_len,
                                        result + 16 + 12,
                                        &aes_gcm_iv[0],
                                        12,
                                        NULL,
                                        0,
                                        (sgx_aes_gcm_128bit_tag_t*)
                                        (result));
        if(ret != SGX_SUCCESS) {
            return ret;
        }
    }
    else {
        ret = (sgx_status_t)0x5002;
        return ret;
    }
    
    return ret;
}


// Process data before publishing
sgx_status_t sum_encrypted_data_s( 
    uint8_t* encrypted_aggregation_msg,
    uint32_t encrypted_aggregation_msg_size,
    sgx_sealed_data_t* publisher_sealed_key,
    sgx_sealed_data_t* storage_sealed_key,
    uint8_t** data_array,
    uint32_t data_count,
    char* publisher_pk,
    uint32_t max_data_size,
    uint8_t* encrypted_result,
    uint32_t* encrypted_result_size)
{
    sgx_status_t ret = SGX_SUCCESS;

    // Unseal keys
    uint8_t publisher_key[16] = {0}; 
    uint32_t publisher_key_size = 16;
    ret = sgx_unseal_data(publisher_sealed_key, NULL, NULL, &publisher_key[0], &publisher_key_size);
    /*
    if(ret != SGX_SUCCESS) {
        uint8_t error = (uint8_t)ret;
        ocall_print_secret(&error, 1);
        return ret;
    }*/

    // Unseal keys
    uint8_t storage_key[16] = {0}; 
    uint32_t storage_key_size = 16;
    ret = sgx_unseal_data(storage_sealed_key, NULL, NULL, &storage_key[0], &storage_key_size);
    /*
    if(ret != SGX_SUCCESS) {
        uint8_t error = (uint8_t)ret;
        ocall_print_secret(&error, 1);
        return ret;
    }*/

    sgx_aes_gcm_128bit_key_t my_key;
    memcpy(my_key, publisher_key, (size_t)publisher_key_size);
    //ocall_print_secret(&publisher_key[0], 16);

    sgx_aes_gcm_128bit_key_t server_key;
    memcpy(server_key, storage_key, (size_t)storage_key_size);
    //ocall_print_secret(&storage_key[0], 16);

    uint32_t publisher_data_size = max_data_size;
    uint8_t* publisher_data = (uint8_t*)malloc((size_t)publisher_data_size);
    
    // Decrypt publisher data
    ret = sgx_rijndael128GCM_decrypt(&my_key,
                                     encrypted_aggregation_msg + 16 + 12,
                                     encrypted_aggregation_msg_size - 16 - 12,
                                     publisher_data,
                                     encrypted_aggregation_msg + 16,
                                     12,
                                     NULL,
                                     0,
                                     (const sgx_aes_gcm_128bit_tag_t*)
                                     (encrypted_aggregation_msg));
    publisher_data_size = encrypted_aggregation_msg_size - 16 - 12;
    if(ret != SGX_SUCCESS) {
        return ret;
    }
    
    // Pick publisher access permissions
    // pk|72d41281|type|weg_multimeter|payload|250|permission1|72d41281
    char access_permissions [1+publisher_data_size];
    memcpy(access_permissions, publisher_data, publisher_data_size);
    access_permissions[publisher_data_size] = 0;
    
    int i = 0;
    char* p_access_permissions = &access_permissions[0];
    char* token = strtok_r(p_access_permissions, "|", &p_access_permissions);
    while (token != NULL && i<5)
    {
        token = strtok_r(NULL, "|", &p_access_permissions);
        i++;
    }
    free(publisher_data);

    uint32_t client_data_size = max_data_size;
    uint8_t* client_data = (uint8_t*)malloc((size_t)client_data_size);

    // Iterate over data array
    unsigned long total = 0;
    memset(client_data,0,max_data_size);
    char payload[128];
    for (uint32_t index = 0; index < data_count; index++) {

        // Separate parameters of stored data
        char* msg = (char*)data_array[index];
        uint32_t encrypted_size;

        i = 0;
        token = strtok_r(msg, "|", &msg);
        while (token != NULL && i<6)
        {
            i++;
            token = strtok_r(NULL, "|", &msg);

            // Get encrypted message size
            if (i == 5) 
                encrypted_size = (uint32_t)strtoul(token,NULL,16);
        }
        
        uint8_t encrypted_data[encrypted_size];
        memcpy(encrypted_data, msg, encrypted_size);

        /* Encrypted data:      | MAC | IV | AES128(data)
         * Buffer size:           16    12   size(data)
         *
         * MAC reference:         &data       :   &data+16
         * IV reference:          &data+16    :   &data+16+12
         * AES128(data) ref:      &data+12+16 : 
         */

        // Decrypt data using key
        ret = sgx_rijndael128GCM_decrypt(&server_key,
                                        encrypted_data + 16 + 12,
                                        encrypted_size - 16 - 12,
                                        client_data,
                                        encrypted_data + 16,
                                        12,
                                        NULL,
                                        0,
                                        (const sgx_aes_gcm_128bit_tag_t*)
                                        (encrypted_data));
        if(ret != SGX_SUCCESS) {
            free(client_data);
            return ret;
        }

        // Verify if publisher can access this data
        // pk|72d41281|type|weg_multimeter|payload|250|permission1|72d41281
       char* p_auxiliar_client_data = (char*)malloc(1+encrypted_size-16-12);
       memcpy(p_auxiliar_client_data, client_data, encrypted_size-16-12);
       p_auxiliar_client_data[encrypted_size-16-12] = 0;

       unsigned long numeric_payload = 0;

       int permission_count = 0;
       bool accepted = false;
        i = 0;
       token = strtok_r(p_auxiliar_client_data, "|", &p_auxiliar_client_data);

       while (token != NULL && accepted == false)
        {
            i++;
            token = strtok_r(NULL, "|", &p_auxiliar_client_data);
            if (i == 7+2*permission_count) {
                if(!memcmp(token, publisher_pk, 8))
                    accepted = true;
                permission_count++;
            }

            // Save payload in memory
            if (i == 5) {
                unsigned j=0;
                while(token[j] != '|' && j<128) { 
                    payload[j] = token[j];
                    j++;
                }
                payload[j] = 0;

                char* invalid_char;
                numeric_payload = strtoul(payload, &invalid_char, 10);
                
                if(payload != 0 && *invalid_char != 0) {
                    ret = (sgx_status_t)0x5003;
                    free(client_data);
                    free(p_auxiliar_client_data);
                    return ret;
                }
            }
        }
        free(p_auxiliar_client_data);
        // client_data = pk|72d41281|type|123456|payload|250|permission1|72d41281

        // Update total
        if(accepted)
            total += numeric_payload;

        memset(client_data,0,max_data_size);
    }
    free(client_data);

    // Build plaintext aggregation data
    char* aggregation_data = (char*)malloc(max_data_size);
    char str[] = "pk|xxxxxxxx|type|555555|payload|";
    memcpy(&str[3],publisher_pk,8);
    memcpy(aggregation_data, &str[0], 32);

    std::string total_string = std::to_string(total);
    memcpy(aggregation_data+32, total_string.c_str(), total_string.length());
    *(aggregation_data+32+total_string.length()) = '|';
    memcpy(aggregation_data+32+total_string.length()+1, p_access_permissions, strlen(p_access_permissions));
    size_t aggregation_data_size = strlen(aggregation_data);

    // Encrypt data using key
    *encrypted_result_size = (uint32_t)(16 + 12 + aggregation_data_size);
    if(max_data_size < *encrypted_result_size) {
        ret = (sgx_status_t)0x5001;
        return ret;
    }

    // ocall_print_secret((uint8_t*)aggregation_data, aggregation_data_size);

    uint8_t aes_gcm_iv[12] = {0};
    memcpy(encrypted_result+16, aes_gcm_iv, 12);
    ret = sgx_rijndael128GCM_encrypt(&server_key,
                                    (uint8_t*)aggregation_data,
                                    (uint32_t)aggregation_data_size,
                                    encrypted_result + 16 + 12,
                                    &aes_gcm_iv[0],
                                    12,
                                    NULL,
                                    0,
                                    (sgx_aes_gcm_128bit_tag_t*)
                                    (encrypted_result));
    if(ret != SGX_SUCCESS) {
        free(aggregation_data);
        return ret;
    }
    free(aggregation_data);
    
    encrypted_result[*encrypted_result_size] = 0;
    
    return ret;
}

sgx_status_t sealing_data(
    uint8_t* sealed_buffer,
    uint32_t sealed_buffer_size,
    uint32_t* real_sealed_size,
    uint8_t* data,
    uint32_t data_size)
{
    *real_sealed_size = sgx_calc_sealed_data_size(0, data_size);
    if (*real_sealed_size == UINT32_MAX)
        return SGX_ERROR_UNEXPECTED;
    if (*real_sealed_size > sealed_buffer_size)
        return SGX_ERROR_INVALID_PARAMETER;

    sgx_status_t err = sgx_seal_data(0, NULL, data_size, data, *real_sealed_size, (sgx_sealed_data_t *)sealed_buffer);
/*
    uint8_t original[16];
    uint32_t original_size = 16;
    ocall_print_secret(data, data_size);
    err = sgx_unseal_data((sgx_sealed_data_t *)sealed_buffer, NULL, NULL, original, &original_size);
    ocall_print_secret((uint8_t*)original, original_size);
*/
    return err;
}


sgx_status_t get_db_request_s(
    uint8_t* encrypted,
    uint32_t encrypted_size,
    char* pk,
    uint32_t max_db_command_size,
    sgx_sealed_data_t* sealed_key,
    char* db_command)
{

    sgx_status_t ret = SGX_SUCCESS;

    // Unseal keys
    uint8_t key[16] = {0}; 
    uint32_t key_size = 16;
    ret = sgx_unseal_data(sealed_key, NULL, NULL, &key[0], &key_size);
    /*
    if(ret != SGX_SUCCESS) {
        uint8_t error = (uint8_t)ret;
        ocall_print_secret(&error, 1);
        return ret;
    }*/

    sgx_aes_gcm_128bit_key_t my_key;
    memcpy(my_key, key, (size_t)key_size);
    //ocall_print_secret(&key[0], 16);

    /* 
    * Decrypt data using key
    *
    * Encrypted data:      | MAC | IV | AES128(data)
    * Buffer size:           16    12   size(data)
    *
    * MAC reference:         &data       :   &data+16
    * IV reference:          &data+16    :   &data+16+12
    * AES128(data) ref:      &data+12+16 : 
    */
    uint32_t publisher_data_size = encrypted_size - 16 - 12;
    uint8_t* publisher_data = (uint8_t*)malloc((size_t)publisher_data_size);
    memset(publisher_data, 0, publisher_data_size);
   
    ret = sgx_rijndael128GCM_decrypt(&my_key,
                                    &encrypted[0] + 16 + 12,
                                    publisher_data_size,
                                    &publisher_data[0],
                                    &encrypted[0] + 16,
                                    12,
                                    NULL,
                                    0,
                                    (const sgx_aes_gcm_128bit_tag_t*)
                                    (&encrypted[0]));
   // ocall_print_secret(&decMessage[0], dec_msg_len);
    if(ret != SGX_SUCCESS) {
        free(publisher_data);
        return ret;
    }

    // Verify if pks are equals
    if(memcmp(pk, publisher_data+3, 8)){
        free(publisher_data);
        ret = (sgx_status_t)0x5001;
        return ret;
    }

    // Pick DB command from data
    int i = 0;
    char* publisher_data_string = (char*)publisher_data;
    char* token = strtok_r(publisher_data_string, "|", &publisher_data_string);
    while (token != NULL) {
        i++;
        token = strtok_r(NULL, "|", &publisher_data_string);

        if(i == 5) {
            size_t db_command_size = strlen(token);
            if(db_command_size > max_db_command_size) {
                free(publisher_data);
                ret = (sgx_status_t)0x5001;
                return ret;
            }
            strncpy(db_command, token, db_command_size);
        }
    }

    free(publisher_data);
    
    return ret;
}


sgx_status_t revoke_data(
    sgx_sealed_data_t* sealed_revoker_key,
    sgx_sealed_data_t* sealed_storage_key,
    uint8_t* encrypted_pk,
    uint8_t* data,
    uint32_t encrypted_data_size, 
    char* pk,
    uint8_t* accepted)
{

    // Verify if nonce is fresh
    // TODO
    
    *accepted = 0;

    sgx_status_t ret = SGX_SUCCESS;

    // Unseal keys
    uint32_t key_size = 16;

    uint8_t revoker_key[16] = {0}; 
    ret = sgx_unseal_data(sealed_revoker_key, NULL, NULL, &revoker_key[0], &key_size);
    /*if(ret != SGX_SUCCESS) {
        uint8_t error = (uint8_t)ret;
        ocall_print_secret(&error, 1);
        return ret;
    }*/

    uint8_t storage_key[16] = {0}; 
    ret = sgx_unseal_data(sealed_storage_key, NULL, NULL, &storage_key[0], &key_size);
    /*if(ret != SGX_SUCCESS) {
        uint8_t error = (uint8_t)ret;
        ocall_print_secret(&error, 1);
        return ret;
    }*/
    
    sgx_aes_gcm_128bit_key_t my_key;
    memcpy(my_key, revoker_key, (size_t)key_size);
    
    sgx_aes_gcm_128bit_key_t server_key;
    memcpy(server_key, storage_key, (size_t)key_size);

    /* 
    * Decrypt pk
    *
    * Encrypted data:      | MAC | IV | AES128(data)
    * Buffer size:           16    12   size(data)
    *
    * MAC reference:         &data       :   &data+16
    * IV reference:          &data+16    :   &data+16+12
    * AES128(data) ref:      &data+12+16 : 
    */
    uint32_t dec_pk_size = 8; 
    uint8_t dec_pk [dec_pk_size+1];
    memset(dec_pk,0,dec_pk_size+1);;
    ret = sgx_rijndael128GCM_decrypt(&my_key,
                                    &encrypted_pk[0] + 16 + 12,
                                    dec_pk_size,
                                    &dec_pk[0],
                                    &encrypted_pk[0] + 16,
                                    12,
                                    NULL,
                                    0,
                                    (const sgx_aes_gcm_128bit_tag_t*)
                                    (&encrypted_pk[0]));
    if(ret != SGX_SUCCESS) {
        return ret;
    }

    // Verify if pks are equals
    if(memcmp(pk, dec_pk, 8)){
        ret = (sgx_status_t)0x5001;
        return ret;
    }

    /* 
    * Decrypt data received from DB/disk copy
    *
    * Encrypted data:      | MAC | IV | AES128(data)
    * Buffer size:           16    12   size(data)
    *
    * MAC reference:         &data       :   &data+16
    * IV reference:          &data+16    :   &data+16+12
    * AES128(data) ref:      &data+12+16 : 
    */
    uint32_t dec_msg_len = encrypted_data_size-12-16; 
    uint8_t decMessage [dec_msg_len];
    memset(decMessage,0,dec_msg_len);;
    ret = sgx_rijndael128GCM_decrypt(&server_key,
                                    &data[0] + 16 + 12,
                                    dec_msg_len,
                                    &decMessage[0],
                                    &data[0] + 16,
                                    12,
                                    NULL,
                                    0,
                                    (const sgx_aes_gcm_128bit_tag_t*)
                                    (&data[0]));
    if(ret != SGX_SUCCESS) {
        return ret;
    }

    // Get permissions and verify if querier is included
    // pk|72d41281|type|123456|payload|250|permission1|72d41281
    
    // Verify if client is the owner of the data
    if(memcmp(decMessage+3, pk, 8)) {
        ret = (sgx_status_t)0x5001;
        return ret;
    }

    // Allow deletion
    *accepted = 1; 

    return ret;
}

