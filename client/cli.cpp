/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Description: command line interface for testting
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>  
#include "client_publish.h"
#include "config_macros.h"  
#include "initialize_communication.h" 
#include <cstdio>  

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
        fprintf(stderr, "client_query not implemented");
    }
    else if (*argv[1] == 'r')
    {
        error = initialize_communication();
    }
    return error;
}