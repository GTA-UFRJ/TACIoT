/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Description: send message quering some data
 */

#include <cstdio>
#include <stdlib.h>
#include <iostream>
#include <string.h>
#include <stdio.h>
#include <chrono>
#include <thread>
#include "utils/encryption.h"

#include "timer.h"
#include "client_query.h"
#include "config_macros.h"
#include HTTPLIB_PATH

int parse_server_response(char* msg, uint8_t* enc_message, uint32_t* size) {

    // size|0x%02x|data|
    //uint32_t index;
    char auxiliar[3];
    char* invalid_char;

    char* token = strtok_r(msg, "|", &msg);
    int i = 0;
    while (token != NULL)
    {
        i++;
        token = strtok_r(NULL, "|", &msg);

        // Get size
        if (i == 1) {
            uint32_t received_size = (uint32_t)strtoul(token, &invalid_char, 16);
            if(received_size == 0 || *invalid_char != 0) {
                printf("\nInvalid data size on the received message.\n");
                return -1;
            }

            // Verify if buffer will overflow
            if(*size < received_size) {
                printf("Data too big\n");
                return -1;
            }
            *size = received_size;
        }

        // Get encrypted
        if (i == 3) {
            
            for (uint32_t j=0; j<*size; j++) {
                auxiliar[0] = token[3*j];
                auxiliar[1] = token[3*j+1];
                auxiliar[2] = '\0';

                enc_message[j] = (uint8_t)strtoul(auxiliar, &invalid_char, 16);
                if(*invalid_char != 0) {
                    printf("\nInvalid encrypted data on the received message.\n");
                    return -1;
                }
            }
            enc_message[*size] = 0;
        }
    }
    return 0;
}

int send_query_message(uint32_t data_index, uint8_t* enc_message, char* command, uint32_t* size)
{
    // Replace SPACE character in command by "_"
    for(unsigned i=0; i<strlen(command); i++) 
        command[i] = (command[i] == ' ') ? '_' : command[i];

    // Build query message
    // http://localhost:7778/query/size=24/pk|72d41281|index|000000
    char http_request[URL_MAX_SIZE];
    char http_response[URL_MAX_SIZE];
    uint32_t message_size = 33+(uint32_t)strlen(command);
    sprintf(http_request, "/query/size=%u/pk|%s|index|%06u|command|%s", message_size, CLIENT_ID, data_index, command);

    // Send query message
    httplib::Error err = httplib::Error::Success;
    httplib::Client cli(SERVER_URL, SERVER_PORT);
    std::this_thread::sleep_for(std::chrono::milliseconds(LATENCY_MS));

    {
        Timer t("communication");
        
        if (auto res = cli.Get(http_request)) {
            printf("Sent %s\n", http_request);

            if (res->status != 200) {
                printf("Server responded with error code: %d\n", (int)res->status);
                return -1;
            }
            else {
                sprintf(http_response,"%s",res->body.c_str());

                if(!strcmp(http_response, "Denied")) {
                    printf("Received: Denied\n");
                    return -1;
                }

                if(parse_server_response(http_response, enc_message, size) != 0) 
                    return -1;
            }

        } else {
            err = res.error();
            printf("Failed to send HTTP message: error %d\n", (int)err);
            return -1;
        }
    }

    return 0;
}

int client_query(uint8_t* key, uint8_t* data, uint32_t data_index, char* command, uint32_t* data_size)
{
    // Send message for quering
    //uint8_t *enc_message = (uint8_t*)malloc(MAX_ENC_DATA_SIZE*sizeof(uint8_t));
    uint32_t enc_message_size = MAX_ENC_DATA_SIZE;
    uint8_t* enc_message = (uint8_t*)malloc(MAX_ENC_DATA_SIZE*sizeof(uint8_t));
    
    if(send_query_message(data_index, enc_message, command, &enc_message_size) != 0) {
        free(enc_message);
        return -1;
    }

    // Decrypt received data
    sample_status_t ret = decrypt_data(key, enc_message, enc_message_size, data, data_size);
    if(ret != SAMPLE_SUCCESS) {
        printf("\nError decrypting client data. Error code: %d\n", (int)ret);
        free(enc_message);
        return -1;
    }
    free(enc_message);

    return 0;
}