/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Description: send data for publishing
 */

#include <stdio.h>
#include "sample_libcrypto.h"   

// Send data for publishing
void send_data_for_publishing(char* , size_t, char*, uint32_t);

// Receive plaintext data, encrypt and send to server for publishing
int client_publish(uint8_t*, uint32_t, char*, uint32_t);