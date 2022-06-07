/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Description: command line interface for testting
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>  
#include <cstdio>  
#include "client_publish.h"
#include "client_query.h"
#include "config_macros.h" 
#include "utils.h" 
#include "initialize_communication.h" 

int main (int argc, char *argv[])
{
    int error;
    if(argc != 2)
        return -1;
    if (*argv[1] == 'p')
    {
        // Fill data buffer
        uint32_t client_data_size = ULTRALIGHT_SIZE; 
        uint32_t data_type_size = DATA_TYPE_SIZE;
        uint8_t client_data[client_data_size];
        for (uint32_t i=0; i<client_data_size; i++)
        {
            client_data[i] = (uint8_t)ULTRALIGHT_SAMPLE[i];
        }
        char data_type[DATA_TYPE_SIZE+1];
        sprintf(data_type,"%s",DATA_TYPE_SAMPLE);
        error = client_publish(client_data, client_data_size, data_type, data_type_size);
    }
    else if (*argv[1] == 'q')
    {
        uint32_t index = 0;
        uint8_t queried_data[MAX_DATA_SIZE];
        uint32_t queried_data_size;
        error = client_query(index, &queried_data_size, queried_data);
        queried_data[queried_data_size] = '\0';
        fprintf(stdout, "Received %s\n", (char*)queried_data);
        debug_print_encrypted(queried_data_size, queried_data);
    }
    else if (*argv[1] == 'r')
        error = initialize_communication();
    else if (*argv[1] == 's') 
        stop_signal();
    return error;
}