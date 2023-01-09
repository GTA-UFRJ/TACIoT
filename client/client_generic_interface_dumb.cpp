/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Description: wrapper for client backend used from both CLI and GUI applications
 */

#include "client_generic_interface_dumb.h"
#include "config_macros.h"
#include <iostream>
#include "errors.h"

int publish_interface(std::string, std::string, std::string, bool){return 0;}
int query_interface(uint32_t index, std::string, std::string* output){
    if(index == 0) 
        *output = std::string("pk|72d41281|type|123456|payload|250");
    else if(index == 1) 
        *output = std::string("pk|72d41281|type|123456|payload|250");
    else if(index == 2) 
        *output = std::string("pk|72d41281|type|123456|payload|250");
    else if(index == 3) 
        *output = std::string("pk|72d41281|type|123456|payload|250");
    else if(index == 4) 
        *output = std::string("time|09/01/2023_15:47:39|pk|83e52392|type|123456|payload|135");
    else if(index == 5) 
        *output = std::string("pk|72d41281|type|123456|payload|279");
    else if(index == 6) 
        *output = std::string("time|09/01/2023_18:00:02|pk|75ac43f1|type|555555|payload|13978");
    else if(index == 7) 
        *output = std::string("time|09/01/2023_22:47:39|pk|83e52392|type|123456|payload|77");
    else if(index == 8) 
        *output = std::string("pk|72d41281|type|123456|payload|250");
    else if(index == 9) 
        *output = std::string("pk|72d41281|type|123456|payload|250");
    else if(index == 10) 
        *output = std::string("pk|72d41281|type|123456|payload|250");
    else if(index == 11) 
        *output = std::string("pk|72d41281|type|123456|payload|250");
    else if(index > 11)
        return (int)OUT_OF_BOUND_INDEX;
    return 0;
}
// revoke
int read_perm_interface(std::string, std::string *){return 0;}
int write_perm_interface(std::string, std::string) {return 0;}
int register_interface(std::string, std::string){return 0;}
int register_ap_interface(std::string, std::string){return 0;}
int read_ap_perm_interface(std::string, std::string* ){return 0;}
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
