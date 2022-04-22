/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Description: send message quering some data
 */

#include <stdio.h>
#include <stdlib.h>
#include "sample_libcrypto.h"   

// Separate size and ecnrypted data from message received
uint32_t parse_server_response(char* , uint8_t* );

// Send message quering some data
size_t send_query_message(uint32_t, uint8_t*);

// Receive query message and send to server 
int client_query(uint32_t,  uint32_t* , uint8_t* );