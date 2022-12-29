/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Description: send registration info for the server
 */

#ifndef _CLIENT_REGISTER_H_
#define _CLIENT_REGISTER_H_ 

#include <stdio.h>
#include "cli.h"

// Send data for publication
int send_registration(char* );

// Receive plaintext data, encrypt and send to server for publishing
int client_register(client_identity_t );

#endif