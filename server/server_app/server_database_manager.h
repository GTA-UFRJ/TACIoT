
#ifndef SERVER_DATABASE_MANAGER_H_
#define SERVER_DATABASE_MANAGER_H_

#include <stdlib.h>
#include <sqlite3.h>
#include <string>
#include "server.h"

typedef struct callback_arg_t
{
    char** datas;
    uint32_t* datas_sizes;
    uint32_t data_count;
} callback_arg_t;

void free_callback_arg(callback_arg_t );

int database_write(sqlite3*, iot_message_t);

int database_read(sqlite3*, char*, char**, uint32_t*, uint32_t*);

#endif