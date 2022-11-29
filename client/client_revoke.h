/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Description: send message revoking some data
 */

#ifndef _CLIENT_REVOKE_H_
#define _CLIENT_REVOKE_H_ 

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// Send message revoking some data
int send_revoke_message(uint32_t, char*, uint32_t, char*, uint8_t*);

// Receive revoke message and send to server 
int client_revoke(uint8_t*, uint32_t, char* );

#endif