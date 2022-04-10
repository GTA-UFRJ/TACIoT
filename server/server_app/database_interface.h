/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Descripton: database write and read functions
 */

#include <stdlib.h>
#include <stdint.h>

// Write to database
int database_write (uint8_t*, uint32_t, uint8_t*, uint32_t);

// Read from database
int databse_read (uint8_t*, uint32_t, uint8_t*, uint8_t*, uint32_t);