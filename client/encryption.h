/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Description: high level data encryption and decryption wrappers
 */

#include <stdlib.h>
#include <stdio.h>
#include "sample_libcrypto.h"   

// Shared key
const sample_aes_gcm_128bit_key_t sha_key[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

void debug_print_encrypted(size_t , uint8_t* );

sample_status_t encrypt_data (size_t* , uint8_t *, uint8_t * , uint32_t);