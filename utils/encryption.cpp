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
#include "timer.h"

sample_status_t encrypt_data (
    uint8_t* key,
    uint8_t* enc_data, 
    uint32_t* enc_data_size,  // return by reference 
    uint8_t* plain_data, 
    uint32_t plain_data_size)
{
    Timer t("encrypt_data");

    const sample_aes_gcm_128bit_key_t formatted_key[16] = 
    {key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7],
     key[8], key[9], key[10],key[11],key[12],key[13],key[14],key[15]};
    const sample_aes_gcm_128bit_key_t (*p_formatted_key)[16];
    p_formatted_key = &formatted_key;

    // Encrypted data:      | MAC | IV | AES128(data)
    // Buffer size:           16    12   size(data)
    // MAC reference:         &data       :   &data+16
    // IV reference:          &data+16    :   &data+16+12
    // AES128(data) ref:      &data+12+16 : 
    sample_status_t ret;

    // Compute result size and verify if the memory will be enough for storing the result
    uint32_t real_size = SAMPLE_AESGCM_MAC_SIZE + SAMPLE_AESGCM_IV_SIZE + plain_data_size;
    if(*enc_data_size < real_size) 
        return SAMPLE_ERROR_OUT_OF_MEMORY;
    *enc_data_size = real_size;

    // Clean result buffer
    memset(enc_data,0,*enc_data_size);

    // Generate nonce (initialization vector IV)
    uint8_t iv[12];
    //srand(time(NULL));
    for(int i=0;i<12;i++) {
        //iv[i] = static_cast<uint8_t>(rand()%10) + 48;
        iv[i] = 0;      // use 0 for testing
    }
    memcpy(enc_data + SAMPLE_AESGCM_MAC_SIZE, iv, SAMPLE_AESGCM_IV_SIZE);

    // Client encrypt data with shared key
    ret = sample_rijndael128GCM_encrypt(
        *p_formatted_key,                                               // 128 bits key = 16 bytes key
        plain_data, plain_data_size,                                    // Origin + origin size
        enc_data + SAMPLE_AESGCM_MAC_SIZE + SAMPLE_AESGCM_IV_SIZE,      // AES128(origin)
        iv, SAMPLE_AESGCM_IV_SIZE,                                      // IV + IV size
        NULL, 0, (sample_aes_gcm_128bit_tag_t *) (enc_data));         // MAC 
    return ret;
}

sample_status_t decrypt_data (
    uint8_t* key,
    uint8_t* enc_data, 
    uint32_t enc_data_size,  
    uint8_t* plain_data, 
    uint32_t* plain_data_size) // return by reference 
{ 
    Timer t("decrypt_data");

    const sample_aes_gcm_128bit_key_t formatted_key[16] = 
    {key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7],
     key[8], key[9], key[10],key[11],key[12],key[13],key[14],key[15]};
    const sample_aes_gcm_128bit_key_t (*p_formatted_key)[16];
    p_formatted_key = &formatted_key;

    // Encrypted data:      | MAC | IV | AES128(data)
    // Buffer size:           16    12   size(data)
    // MAC reference:         &data       :   &data+16
    // IV reference:          &data+16    :   &data+16+12
    // AES128(data) ref:      &data+12+16 : 
    sample_status_t ret;

    // Compute result size and verify if the memory will be enough for storing the result
    uint32_t real_size = enc_data_size - SAMPLE_AESGCM_MAC_SIZE - SAMPLE_AESGCM_IV_SIZE;
    if(*plain_data_size < real_size)
        return SAMPLE_ERROR_OUT_OF_MEMORY;
    *plain_data_size = real_size;

    // Clean result buffer
    memset(plain_data,0,*plain_data_size);

    // Client decrypt data with shared key
    ret = sample_rijndael128GCM_encrypt(
        *p_formatted_key,                                               // 128 bits key = 16 bytes key
        enc_data + SAMPLE_AESGCM_MAC_SIZE +SAMPLE_AESGCM_IV_SIZE, 
        *plain_data_size,                                               // Origin + origin size
        plain_data,                                                     // AES128(origin)
        enc_data + SAMPLE_AESGCM_MAC_SIZE, SAMPLE_AESGCM_IV_SIZE,       // IV + IV size
        NULL, 0, (sample_aes_gcm_128bit_tag_t *) (enc_data));           // MAC 

    return ret;
}

void quick_decrypt_debug (uint8_t* key, uint8_t* enc, uint32_t enc_size) {
    uint32_t plain_size = enc_size - 12 - 16;
    uint8_t plain[plain_size+1];
    decrypt_data(key, enc, enc_size, plain, &plain_size);
    plain[plain_size] = '\0';
    printf("Decrypted: %s\n", (char*)plain);
}