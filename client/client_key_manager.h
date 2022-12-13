/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Description: configure key and ID
 */

#ifndef _CLIENT_KEY_MANAGER_H_
#define _CLIENT_KEY_MANAGER_H_

#include <stdio.h>
#include <stdlib.h>
#include "config_macros.h"
#include HTTPLIB_PATH
#include "cli.h"

int parse_configure_key_message(char*, client_identity_t* );

int get_configure_key_message(const httplib::Request& , char* , uint32_t* );

int read_identity(client_identity_t* );

int write_identity(client_identity_t );

int configure_device(client_identity_t );

#endif