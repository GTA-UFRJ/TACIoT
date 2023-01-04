/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Description: wrapper for client backend used from both CLI and GUI applications
 */

#include "client_generic_interface_dumb.h"
#include "config_macros.h"
#include <iostream>

int publish_interface(std::string, std::string, std::string){return 0;}
int query_interface(uint32_t, std::string, std::string*){return 0;}
// revoke
int read_perm_interface(std::string, std::string *){return 0;}
int read_perms_interface(){return 0;}
int write_perm_interface(std::string, std::string) {return 0;}
int register_interface(std::string, std::string){return 0;}
int register_ap_interface(std::string, std::string){return 0;}
int read_ap_perms_interface(std::string*){return 0;}
int write_ap_perm_interface(std::string, std::string){return 0;} // Second argument is in format xxxxxxxx xxxxxxxx ... xxxxxxxx

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
