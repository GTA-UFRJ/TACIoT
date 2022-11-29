/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Description: manages the r/w operations in the database and key vault
 */


#ifndef SERVER_DATABASE_MANAGER_H_
#define SERVER_DATABASE_MANAGER_H_

#include <stdlib.h>
#include <sqlite3.h>
#include <string>
#include "server.h"
#include "errors.h"

typedef struct callback_arg_t
{
    char** datas;
    uint32_t* datas_sizes;
    uint32_t data_count;
} callback_arg_t;

void free_callback_arg(callback_arg_t );

server_error_t database_write(sqlite3*, iot_message_t);

server_error_t database_read(sqlite3*, char*, char**, uint32_t*, uint32_t*);

server_error_t database_delete(sqlite3*, stored_data_t);

#endif