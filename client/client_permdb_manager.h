/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Description: manages the r/w operations concerning deafult access permissions
 */

#ifndef _CLIENT_PERMDB_MANAGER_H_
#define _CLIENT_PERMDB_MANAGER_H_

#include <stdlib.h>
#include <sqlite3.h>
#include <string>
#include "config_macros.h"
#include "cli.h"
#include HTTPLIB_PATH

typedef struct callback_arg_t
{
    char** datas;
    uint32_t data_count;
} callback_arg_t;

int parse_configure_perms_message(char*, default_perms_t* );

int get_configure_perms_message(const httplib::Request& , char* , uint32_t* );

int read_default_perms(sqlite3*, char*, char**, uint32_t*);

int write_default_perms(sqlite3*, char*, char**, uint32_t);

#endif