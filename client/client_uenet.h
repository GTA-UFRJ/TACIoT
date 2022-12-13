/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Description: network interface for the user equipament to configure the AP
 */

#ifndef _CLIENT_UENET_H_
#define _CLIENT_UENET_H_ 

#include <stdio.h>
#include "cli.h"

int send_register_ap_message(client_identity_t );

int send_ap_perms_message(default_perms_t );

#endif