/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Description: manages the r/w operations in the database and key vault
 */

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

int file_write(iot_message_t, uint8_t*, uint32_t);

// Separate parameters of stored message
int get_stored_parameters(char*, stored_data_t*);

// Locate data in file and read it 
int file_read(uint32_t , char* );

// Count number of lines in file
uint32_t count_entries();

// Verify if file alredy exists
bool verify_file_existance(char*);

// Write client key to file
int write_key(char*, uint8_t*, uint32_t, char*);