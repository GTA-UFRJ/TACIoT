/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Description: manages the r/w operations in the database and key vault
 */

#ifndef _SERVER_DISK_MANAGER_
#define _SERVER_DISK_MANAGER_

#include <stdlib.h>
#include <iostream>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#include "sample_libcrypto.h"   // sample_aes_gcm_128bit_key_t
#include "server.h"
#include "timer.h"

#include "config_macros.h"      // ULTRALIGH_SAMPLE
#include "utils_sgx.h"
#include "utils.h"
#include "errors.h"

// Separate parameters of stored message
server_error_t get_stored_parameters(char*, stored_data_t*);

// Verify if file alredy exists
bool verify_file_existance(char*);

// Write client key to file
int write_key(uint8_t*, uint32_t, char*);

#endif