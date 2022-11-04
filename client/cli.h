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

void print_usage();

void free_client_data(client_data_t );

#endif
