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
#include "cli.h"

void free_permissions_array(char** permissions_list, uint32_t permissions_count) {
    for(unsigned i = 0; i < permissions_count; i++)
        free(permissions_list[i]);
    free(permissions_list);
}

void print_usage() {
    printf("Usage examples:\n");
    printf("Example for publishing a data of type 123456, payload 250 and permission for 72d41281\n");
    printf("./Client publish 123456 250 72d41281\n\n");
    printf("Example for publishing a data of type 123456, payload 250 and default access permissions\n");
    printf("./Client publish 123456 250 default\n\n");
    printf("Example for publishing a data of type 555555, payload \"SELECT * from TACIOT where type='123456'\" and permission for 72d41281\n");
    printf("./Client publish 555555 \"SELECT * from TACIOT where type='123456'\" 72d41281\n\n");
    printf("Example for querying a data using SQL command \"SELECT * from TACIOT where type='123456'\" of index 0\n");
    printf("./Client query 0 \"SELECT * from TACIOT where type='123456'\"\n\n");
    printf("Example for revoking a data using SQL command \"SELECT * from TACIOT where type='123456'\" of index 0\n");
    printf("./Client revoke 0 \"SELECT * from TACIOT where type='123456'\"\n\n");
    printf("Example for reading default access permissions for type='123456'\n");
    printf("./Client read_perm 123456\n\n");
    printf("Example for writing default access permissions for type='123456'\n");
    printf("./Client write_perm 123456 72d41281\n\n");
    printf("Example for registering client with ID 72d41281 and key equals to 16 bytes of zero\n");
    printf("./Client register 72d41281 00000000000000000000000000000000\n\n");
    printf("Example for registering access point with ID 72d41281 and key equals to 16 bytes of zero\n");
    printf("./Client register_ap 72d41281 00000000000000000000000000000000\n\n");
    printf("Example for writing on the access point default access permissions for type='123456'\n");
    printf("./Client ap_perm 123456 72d41281\n\n");
    printf("Example for initializing access point\n");
    printf("./Client ap_init\n\n");
}

void free_client_data(client_data_t data) {
    free(data.payload);
    for(unsigned i=0; i<data.permissions_count; i++)
        free(data.permissions_list[i]);
    free(data.permissions_list);
}

int main (int argc, char *argv[]) {

    if(argc < 2) { 
        printf("Too less arguments\n");
        print_usage();
        return -1;
    }

    if (!strcmp(argv[1],"publish"))
        return publish_interface(argc, argv);

    else if (!strcmp(argv[1],"query"))
        return query_interface(argc, argv);

    else if (!strcmp(argv[1],"revoke"))
        return revoke_interface(argc, argv);

    else if (!strcmp(argv[1],"read_perm"))
        return read_perm_interface(argc, argv);

    else if (!strcmp(argv[1],"write_perm"))
        return write_perm_interface(argc, argv);

    else if (!strcmp(argv[1],"register")) 
        return register_interface(argc, argv);

    else if (!strcmp(argv[1],"register_ap")) 
        return register_ap_interface(argc, argv);

    else if (!strcmp(argv[1],"ap_perm"))
        return write_ap_perm_interface(argc, argv);

    else if (!strcmp(argv[1],"ap_init"))
    {
        if(argc != 2) {
            printf("Invalid number of arguments arguments\n");
            print_usage();
            return -1;
        }

        return initialize_ap_server();
    }
    
    else {
        printf("Invalid message\n");
        print_usage();
        return -1;
    }
    
    return 0;
}