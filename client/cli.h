/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Description: command line interface for testting
 */

#include <stdint.h>

//typedef enum { General, Publication, Query, Register} operation_type_t; 

#ifndef _CLI_H_
#define _CLI_H_

typedef struct client_data {
    char pk[9];
    char type[7];
    char* payload;
    uint32_t permissions_count;
    char** permissions_list;
} client_data_t;

typedef struct client_identity {
    char pk[9];
    uint8_t comunication_key[16];
} client_identity_t;

typedef struct default_perms {
    char type[7];
    uint32_t permissions_count;
    char** permissions_list;
} default_perms_t;


#endif
