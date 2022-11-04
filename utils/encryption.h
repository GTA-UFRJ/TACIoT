/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Description: high level data encryption and decryption wrappers
 */

#ifndef ENCRYPTION_H_
#define ENCRYPTION_H_

#include <stdlib.h>
#include <stdio.h>
#include "sample_libcrypto.h"   

sample_status_t encrypt_data (uint8_t* ,uint8_t* , uint32_t* , uint8_t* , uint32_t );

sample_status_t decrypt_data (uint8_t* ,uint8_t* , uint32_t , uint8_t* , uint32_t* );

void quick_decrypt_debug (uint8_t* , uint8_t* , uint32_t );

#endif