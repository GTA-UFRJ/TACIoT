/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Description: wrapper for client backend used from both CLI and GUI applications
 */

#ifndef _CLIENT_GENERIC_INTERFACE_H_
#define _CLIENT_GENERIC_INTERFACE_H_

#include "errors.h"
#include <string>

int publish_interface(int agrc, char** argv);
int query_interface(int argc, char** argv);
int revoke_interface(int argc, char** argv);
int read_perm_interface(int argc, char** argv );
int read_perms_interface(int argc, char** argv );
int write_perm_interface(int argc, char** argv );
int register_interface(int argc, char** argv );
int register_ap_interface(int argc, char** argv );
int write_ap_perm_interface(int argc, char** argv ); 
int read_ap_perms_interface(int argc, char** argv ); 
int ap_init_interface(int argc, char** argv );

// Overloaded alternatives
int publish_interface(std::string, std::string, std::string);
int query_interface(uint32_t, std::string, std::string*);
//revoke
int read_perm_interface(std::string, std::string *);
int read_perms_interface();
int write_perm_interface(std::string, std::string);
int register_interface(std::string, std::string);
int register_ap_interface(std::string, std::string);
int read_ap_perms_interface();
int write_ap_perm_interface(std::string, std::string);
//ap_init

/*
void allocate_argv(char** argv, int argc);
void free_argv(char** argv, int argc);
*/
#endif
