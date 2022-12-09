/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Description: command line interface for testting
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>  
#include <cstdio>  
#include "client_permdb_manager.h"
#include "client_publish.h"
#include "client_revoke.h"
#include "client_query.h"
#include "config_macros.h" 
#include "utils.h" 
#include "errors.h"
#include "cli.h"

void free_permissions_array(char** permissions_list, uint32_t permissions_count) {
    for(unsigned i = 0; i < permissions_count; i++)
        free(permissions_list[i]);
    free(permissions_list);
}

// Secret key for encryption
uint8_t global_key[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

void print_usage() {
    printf("Usage examples:\n");
    printf("Example for publishing a data of type 123456, payload 250 and permission for 72d4128\n");
    printf("./Client publish 123456 250 72d41281\n\n");
    printf("Example for publishing a data of type 123456, payload 250 and default access permissions\n");
    printf("./Client publish 123456 250 default\n\n");
    printf("Example for publishing a data of type 555555, payload \"SELECT * from TACIOT where type='123456'\" and permission for 72d4128\n");
    printf("./Client publish 555555 \"SELECT * from TACIOT where type='123456'\" 72d41281\n\n");
    printf("Example for querying a data using SQL command \"SELECT * from TACIOT where type='123456'\" of index 0\n");
    printf("./Client query 0 \"SELECT * from TACIOT where type='123456'\"\n\n");
    printf("Example for revoking a data using SQL command \"SELECT * from TACIOT where type='123456'\" of index 0\n");
    printf("./Client revoke 0 \"SELECT * from TACIOT where type='123456'\"\n\n");
    printf("Example for reading default access permissions for type='123456'\n");
    printf("./Client read_perm 123456\n\n");
    printf("Example for writing default access permissions for type='123456'\n");
    printf("./Client write_perm 123456 72d41281\n\n");
}

void free_client_data(client_data_t data) {
    free(data.payload);
    for(unsigned i=0; i<data.permissions_count; i++)
        free(data.permissions_list[i]);
    free(data.permissions_list);
}

int main (int argc, char *argv[]) {

    int ret = 0;

    if(argc < 2) { 
        printf("Too less arguments\n");
        print_usage();
        return -1;
    }

    if (!strcmp(argv[1],"publish"))
    {
        if(argc < 5) {
            printf("Too less arguments\n");
            print_usage();
            return -1;
        }

        // Fill client data structure
        client_data_t data;
        data.payload = (char*)malloc(strlen(argv[3])+1);

        sprintf(data.pk, "%s", PK_SAMPLE);
        sprintf(data.type, "%s", argv[2]);
        sprintf(data.payload, "%s", argv[3]);

        // Pick permissions
        if(!strcmp(argv[4], "default")) {
            sqlite3 *db;

            if(sqlite3_open(DEFAULT_PERMS_DB_PATH, &db)) {
                printf("SQL error: %s\n", sqlite3_errmsg(db));
                return print_error_message(OPEN_DATABASE_ERROR);
            }
            
            data.permissions_list = (char**)malloc(MAX_NUM_PERMISSIONS*sizeof(char*));
            ret = read_default_perms(db, argv[2],  data.permissions_list, &data.permissions_count);
            if(ret) {
                free_client_data(data);
                printf("Error reading permissions from database\n");
                return -1;
            }
        }
        else {
            data.permissions_count = argc - 4;
            data.permissions_list = (char**)malloc(data.permissions_count*sizeof(char*));
            for(int i=4; i<argc; i++) {
                data.permissions_list[i-4] = (char*)malloc(9);
                sprintf(data.permissions_list[i-4], "%s", argv[i]);
            }
        }

        // Publish data
        ret = client_publish(global_key, data);
        free_client_data(data);
    }
    else if (!strcmp(argv[1],"query"))
    {
        if(argc < 4) {
            printf("Too less arguments\n");
            print_usage();
            return -1;
        }
        else if(argc > 4) {
            printf("Too many arguments\n");
            print_usage();
            return -1;
        }

        char* invalid_char;
        uint32_t index = (uint32_t)strtoul(argv[2],&invalid_char,10);

        if(*invalid_char != 0) {
            printf("\nInvalid argument.\n");
            print_usage();
            return -1;
        }

        char* command = (char*)malloc(strlen(argv[3])+1);
        sprintf(command, "%s", argv[3]);

        uint32_t queried_data_size = MAX_DATA_SIZE;
        uint8_t queried_data[queried_data_size];

        ret = client_query(global_key, queried_data, index, command, &queried_data_size);
        free(command);

        if(!ret) {
            queried_data[queried_data_size] = 0;
            printf("Received: %s\n", (char*)queried_data);
        }
    }

    else if (!strcmp(argv[1],"revoke"))
    {
        if(argc < 4) {
            printf("Too less arguments\n");
            print_usage();
            return -1;
        }
        else if(argc > 4) {
            printf("Too many arguments\n");
            print_usage();
            return -1;
        }

        char* invalid_char;
        uint32_t index = (uint32_t)strtoul(argv[2],&invalid_char,10);

        if(*invalid_char != 0) {
            printf("\nInvalid argument.\n");
            print_usage();
            return -1;
        }

        char* command = (char*)malloc(strlen(argv[3])+1);
        sprintf(command, "%s", argv[3]);

        if(client_revoke(global_key, index, command) != 0) {
            free(command);
            return -1;
        }
        
        free(command);
    }

    else if (!strcmp(argv[1],"read_perm"))
    {
        if(argc != 3) {
            printf("Invalid number of arguments\n");
            print_usage();
            return -1;
        }

        // Open deafult access permissions database
        sqlite3 *db;

        if(sqlite3_open(DEFAULT_PERMS_DB_PATH, &db)) {
            printf("SQL error: %s\n", sqlite3_errmsg(db));
            return print_error_message(OPEN_DATABASE_ERROR);
        } 

        // Read access permissions for type in database
        char** permissions = (char**)malloc(MAX_NUM_PERMISSIONS*sizeof(char*));
        uint32_t permissions_count;
        ret = read_default_perms(db, argv[2],  permissions, &permissions_count);
        if(ret) {
            free_permissions_array(permissions, permissions_count);
            printf("Error reading from database\n");
            return -1;
        }

        // Print access permissions
        for(uint32_t index=0; index<permissions_count; index++)
            printf("%s\n", permissions[index]);
        free_permissions_array(permissions, permissions_count);
    }

    else if (!strcmp(argv[1],"write_perm"))
    {
        if(argc < 4) {
            printf("Too less arguments\n");
            print_usage();
            return -1;
        }

        // Open deafult access permissions database
        sqlite3 *db;

        if(sqlite3_open(DEFAULT_PERMS_DB_PATH, &db)) {
            printf("SQL error: %s\n", sqlite3_errmsg(db));
            return print_error_message(OPEN_DATABASE_ERROR);
        } 

        // Prepare array with data permissions
        uint32_t permissions_count = argc - 3;
        char** permissions = (char**)malloc(permissions_count*sizeof(char*));
        for(uint32_t index=0; index<permissions_count; index++) {
            permissions[index] = (char*)malloc(9);
            strcpy(permissions[index], argv[index+3]);
        }

        // Write access permissions for type in database
        ret = write_default_perms(db, argv[2],  permissions, permissions_count);
        free_permissions_array(permissions, permissions_count);
        if(ret) {
            printf("Error writing to database\n");
            return -1;
        }

    }

    else if (*argv[1] == 'r') {
        //send_key();
        ;
    }
    else {
        printf("Invalid message\n");
        print_usage();
        return -1;
    }
    
    return ret;
}