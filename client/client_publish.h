/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Description: send data for publishing
 */

#include <stdio.h>
#include "cli.h"

// Send data for publication
int send_data_for_publication(char*, char*, uint8_t*, uint32_t);

// Receive plaintext data, encrypt and send to server for publishing
int client_publish(uint8_t*, client_data_t);