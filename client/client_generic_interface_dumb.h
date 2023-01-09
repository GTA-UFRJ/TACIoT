/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Description: wrapper for client backend used from both CLI and GUI applications
 */

#ifndef _CLIENT_GENERIC_INTERFACE_H_
#define _CLIENT_GENERIC_INTERFACE_H_

#include "errors.h"
#include <string>

// Overloaded alternatives
int publish_interface(std::string, std::string, std::string, bool);
int query_interface(uint32_t, std::string, std::string*);
//revoke
int read_perm_interface(std::string, std::string *);
int write_perm_interface(std::string, std::string);
int register_interface(std::string, std::string);
int register_ap_interface(std::string, std::string);
int read_ap_perm_interface(std::string, std::string*);
int write_ap_perm_interface(std::string, std::string);
//ap_init

/*
void allocate_argv(char** argv, int argc);
void free_argv(char** argv, int argc);
*/
#endif
