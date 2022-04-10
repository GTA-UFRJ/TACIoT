/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Description: codes for processing data
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

typedef enum proc_code_t{
    none,
    generic_test
} proc_code_t;

// Use type to determine how to process data
proc_code_t detect_processing_code(char*);

// Process data
void apply_processing(unsigned int, uint8_t*, uint32_t, uint8_t*);

// Do not apply any processing
void none_proc();

// Apply test processing for future benchmarking
void generic_test_proc();