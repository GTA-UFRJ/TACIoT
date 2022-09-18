/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Description: high level data encryption and decryption wrappers
 */

#include <stdlib.h>
#include <stdio.h>
#include "sample_libcrypto.h"   
#include "encryption.h"
#include <chrono>
#include <string.h>

sample_status_t encrypt_data (
    size_t* encMessageLen, 
    uint8_t* encMessage, 
    uint8_t* client_data, 
    uint32_t client_data_size)
{

    // Encrypted data:      | MAC | IV | AES128(data)
    // Buffer size:           16    12   size(data)
    // MAC reference:         &data       :   &data+16
    // IV reference:          &data+16    :   &data+16+12
    // AES128(data) ref:      &data+12+16 : 
    sample_status_t ret;
    *encMessageLen = SAMPLE_AESGCM_MAC_SIZE + SAMPLE_AESGCM_IV_SIZE + client_data_size;
    const sample_aes_gcm_128bit_key_t (*key)[16];
    key = &sha_key;

    // Generate nonce (initialization vector IV)
    uint8_t iv[12];
    //srand(time(NULL));
    for(int i=0;i<12;i++)
    {
        //iv[i] = static_cast<uint8_t>(rand()%10) + 48;
        iv[i] = 0;
    }
    memcpy(encMessage + SAMPLE_AESGCM_MAC_SIZE, iv, SAMPLE_AESGCM_IV_SIZE);

    // Client encrypt data with shared key
    ret = sample_rijndael128GCM_encrypt(
        *key,                                                           // 128 bits key = 16 bytes key
        client_data, client_data_size,                                  // Origin + origin size
        encMessage + SAMPLE_AESGCM_MAC_SIZE + SAMPLE_AESGCM_IV_SIZE,    // AES128(origin)
        iv, SAMPLE_AESGCM_IV_SIZE,                                      // IV + IV size
        NULL, 0, (sample_aes_gcm_128bit_tag_t *) (encMessage));         // MAC 
    if(ret == SAMPLE_SUCCESS) printf("ENCRYPT RESULT: SAMPLE_SUCCESS");
    if(ret == SAMPLE_ERROR_INVALID_PARAMETER) printf("ENCRYPT RESULT: SAMPLE_ERROR_INVALID_PARAMETER");
    if(ret == SAMPLE_ERROR_OUT_OF_MEMORY) printf("ENCRYPT RESULT: SAMPLE_ERROR_OUT_OF_MEMORY");
    if(ret == SAMPLE_ERROR_UNEXPECTED) printf("ENCRYPT RESULT: SAMPLE_ERROR_UNEXPECTED");
    printf("\n");


    return ret;
}

sample_status_t decrypt_data
 (
    size_t encMessageLen, 
    uint8_t* encMessage, 
    uint8_t* client_data, 
    uint32_t* client_data_size)
{

    // Encrypted data:      | MAC | IV | AES128(data)
    // Buffer size:           16    12   size(data)
    // MAC reference:         &data       :   &data+16
    // IV reference:          &data+16    :   &data+16+12
    // AES128(data) ref:      &data+12+16 : 
    sample_status_t ret;
    *client_data_size = (uint32_t)encMessageLen - SAMPLE_AESGCM_MAC_SIZE - SAMPLE_AESGCM_IV_SIZE;
    const sample_aes_gcm_128bit_key_t (*key)[16];
    key = &sha_key;

    // Client decrypt data with shared key
    ret = sample_rijndael128GCM_encrypt(
        *key,                                                           // 128 bits key = 16 bytes key
        encMessage + SAMPLE_AESGCM_MAC_SIZE +SAMPLE_AESGCM_IV_SIZE, 
        *client_data_size,                                              // Origin + origin size
        client_data,                                                    // AES128(origin)
        encMessage + SAMPLE_AESGCM_MAC_SIZE, SAMPLE_AESGCM_IV_SIZE,     // IV + IV size
        NULL, 0, (sample_aes_gcm_128bit_tag_t *) (encMessage));         // MAC 
    if(ret == SAMPLE_SUCCESS) printf("DECRYPT RESULT: SAMPLE_SUCCESS");
    if(ret == SAMPLE_ERROR_INVALID_PARAMETER) printf("DECRYPT RESULT: SAMPLE_ERROR_INVALID_PARAMETER");
    if(ret == SAMPLE_ERROR_OUT_OF_MEMORY) printf("DECRYPT RESULT: SAMPLE_ERROR_OUT_OF_MEMORY");
    if(ret == SAMPLE_ERROR_UNEXPECTED) printf("DECRYPT RESULT: SAMPLE_ERROR_UNEXPECTED");
    printf("\n");

    return ret;
}