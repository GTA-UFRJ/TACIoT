/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Description: send message quering some data
 */

#ifndef _CLIENT_QUERY_H_
#define _CLIENT_QUERY_H_ 

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// Separate size and ecnrypted data from message received
int parse_server_response(char*, uint8_t*, uint32_t* );

// Send message quering some data
int send_query_message(uint32_t, uint8_t*, uint32_t*, char*, uint32_t, uint8_t* );

// Receive query message and send to server 
int client_query(uint8_t*, uint8_t*, uint32_t, char*, uint32_t* );

#endif