/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Description: wrapper for client backend used from both CLI and GUI applications
 */

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>  
#include <cstdio>  
#include "client_permdb_manager.h"
#include "client_key_manager.h"
#include "client_publish.h"
#include "client_revoke.h"
#include "client_query.h"
#include "client_apnet.h"
#include "client_uenet.h"
#include "client_register.h"
#include "client_generic_interface.h"
#include "config_macros.h" 
#include "utils.h" 
#include "errors.h"

int publish_interface(int argc, char** argv) 
{
    int ret = 0;

    if(argc < 5) {
        printf("Too less arguments\n");
        print_usage();
        return -1;
    }
    
    client_identity_t id;
    if(read_identity(&id))
        return -1;
    
    // Fill client data structure
    client_data_t data;
    data.payload = (char*)malloc(strlen(argv[3])+1);
    sprintf(data.pk, "%s", id.pk);
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
    ret = client_publish(id.comunication_key, data);
    free_client_data(data);
    return ret;
}

int query_interface(int argc, char** argv)
{
    int ret = 0;

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
    
    client_identity_t id;
    if(read_identity(&id))
        return -1;

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
    ret = client_query(id.comunication_key, queried_data, index, command, &queried_data_size, id.pk);
    free(command);

    if(!ret) {
        queried_data[queried_data_size] = 0;
        printf("Received: %s\n", (char*)queried_data);
    }
    return ret;
}

int revoke_interface(int argc, char** argv)
{
    int ret = 0;

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
        
    client_identity_t id;
    if(read_identity(&id))
        return -1;

    char* invalid_char;
    uint32_t index = (uint32_t)strtoul(argv[2],&invalid_char,10);

    if(*invalid_char != 0) {
        printf("\nInvalid argument.\n");
        print_usage();
        return -1;
    }

    char* command = (char*)malloc(strlen(argv[3])+1);
    sprintf(command, "%s", argv[3]);

    ret = client_revoke(id.comunication_key, index, command, id.pk);
    free(command);
    return ret;
}

int read_perm_interface(int argc, char** argv)
{
    int ret = 0;
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
    return 0;
}

int read_perms_interface(int argc, char** argv)
{
    printf("Not implemented\n");
    return 0;
}

int write_perm_interface(int argc, char** argv)
{
    int ret = 0;
    
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
    return ret;
}

int register_interface(int argc, char** argv)
{
    int ret = 0;

    if(argc != 4) {
        printf("Invalid number of arguments\n");
        print_usage();
        return -1;
    }

    // Fill structure with ID (pk) and communication key (CC)
    client_identity_t id;
    strcpy(id.pk, argv[2]);

    char byte_auxiliar[3];
    char* invalid_char;
    for(uint32_t index=0; index<16; index++) {

        sprintf(byte_auxiliar, "%c%c", argv[3][2*index], argv[3][2*index+1]);
        id.comunication_key[index] = (uint8_t)strtoul(byte_auxiliar, &invalid_char, 16);

        if(byte_auxiliar != 0 && *invalid_char != 0) 
            return (int)print_error_message(INVALID_ENCRYPTED_FIELD_ERROR);
    }
    //debug_print_encrypted(16, (uint8_t*)(id.comunication_key));

    //return configure_device(id);
    // Write identity into a file
    ret = write_identity(id);
    if (ret) 
        return ret;

    // Register client in the server
    return client_register(id);    
}

int register_ap_interface(int argc, char** argv)
{
    int ret = 0;

    if(argc != 4) {
        printf("Invalid number of arguments\n");
        print_usage();
        return -1;
    }

    // Fill structure with ID (pk) and communication key (CC)
    client_identity_t id;
    strcpy(id.pk, argv[2]);

    char byte_auxiliar[3];
    char* invalid_char;
    for(uint32_t index=0; index<16; index++) {

        sprintf(byte_auxiliar, "%c%c", argv[3][2*index], argv[3][2*index+1]);
        id.comunication_key[index] = (uint8_t)strtoul(byte_auxiliar, &invalid_char, 16);

        if(byte_auxiliar != 0 && *invalid_char != 0) 
            return (int)print_error_message(INVALID_ENCRYPTED_FIELD_ERROR);
    }

    return send_register_ap_message(id);
}

int read_ap_perms_interface(int argc, char** argv)
{
    return 0;
}

int write_ap_perm_interface(int argc, char** argv)
{
    int ret = 0;
    
    if(argc < 4) {
        printf("Too less arguments\n");
        print_usage();
        return -1;
    }

    // Prepare array with data permissions
    default_perms_t perms;
    strcpy(perms.type, argv[2]);
    perms.permissions_count = argc - 3;
    perms.permissions_list = (char**)malloc(perms.permissions_count*sizeof(char*));
    for(uint32_t index=0; index<perms.permissions_count; index++) {
        (perms.permissions_list)[index] = (char*)malloc(9);
        strcpy((perms.permissions_list)[index], argv[index+3]);
    }

    ret = send_ap_perms_message(perms);
    free_permissions_array(perms.permissions_list, perms.permissions_count);
    return ret;
}





// -------------------- OVERLOADS --------------------





// TODO

int publish_interface(std::string type, std::string sql_statement, std::string perms)
{
    return 0;
}

int query_interface(uint32_t index, std::string sql_statement, std::string* returned_query)
{
    return 0;
}

// revoke

int read_perm_interface(std::string type, std::string* returned_ids)
{
    return 0;
}

int read_perms_interface()
{
    return 0;
}

int write_perm_interface(std::string type, std::string perms) 
{
    return 0;
}

int register_interface(std::string id, std::string ck)
{
    return 0;
}

int register_ap_interface(std::string id, std::string ck)
{
    return 0;
}

int read_ap_perms_interface()
{
    return 0;
}

int write_ap_perm_interface(std::string type, std::string perms)  // Second argument is in format xxxxxxxx xxxxxxxx ... xxxxxxxx
{
    return 0;
}


/*
void allocate_argv(char** argv, int argc) {
    argv = (char**)malloc(argc*sizeof(char*));
    for(unsigned i=0; i<argc; i++)
        argv[i] = (char*)malloc(MAX_ARG_SIZE);
}

void free_argv(char** argv, int argc) {
    for(unsigned i=0; i<argc; i++)
        free(argv[i]);
    free(argv);
}
*/
