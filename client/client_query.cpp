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
#include "errors.h"

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
                return (int)print_error_message(INVALID_HTTP_RESPONSE_SIZE_FIELD_ERROR);
            }

            // Verify if buffer will overflow
            if(*size < received_size) {
                printf("Data too big\n");
                return (int)print_error_message(HTTP_RESPONSE_SIZE_OVERFLOW_ERROR);
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
                if(*invalid_char != 0) 
                    return (int)print_error_message(INVALID_ENCRYPTED_RESPONSE_ERROR);
            }
            enc_message[*size] = 0;
        }
    }
    return 0;
}

int send_query_message(uint32_t data_index, 
                       uint8_t* enc_message, 
                       uint32_t* enc_message_size,
                       char* command, 
                       uint32_t command_size,
                       uint8_t* enc_pk)
{
    int ret = 0;

    // Replace SPACE character in command by "_"
    for(unsigned i=0; i<strlen(command); i++) 
        command[i] = (command[i] == ' ') ? '_' : command[i];

    // Build query message
    // http://localhost:7778/query/size=24/pk|72d41281|index|000000
    char* http_request = (char*)malloc(URL_MAX_SIZE);
    uint32_t message_size = 53+(uint32_t)strlen(command)+(8+16+12)*3;
    sprintf(http_request, "/query/size=%u/pk|%s|index|%06u|size|%02x|command|%s|encrypted|", 
    message_size, CLIENT_ID, data_index, command_size, command);

    char auxiliar[4];
    for (uint32_t i=0; i<8+16+12; i++) {
        sprintf(auxiliar, "%02x-",enc_pk[i]);
        memcpy(http_request+strlen(http_request), auxiliar, 3);
    }
    
    // Send query message
    httplib::Error err = httplib::Error::Success;
    httplib::Client cli(SERVER_URL, SERVER_PORT);
    std::this_thread::sleep_for(std::chrono::milliseconds(LATENCY_MS));

    {
        Timer t("communication");
        
        printf("Sent %s\n", http_request);
        auto res = cli.Get(http_request);
        free(http_request);
        if (res) {

            if (res->status != 200) {
                printf("Error code: %d\n", (int)res->status);
                return (int)print_error_message(HTTP_RESPONSE_ERROR);
            }
            
            char* http_response = (char*)malloc(URL_MAX_SIZE);
            sprintf(http_response,"%s",res->body.c_str());
            if(!strncmp(http_response, "size", 4)) {
                ret = parse_server_response(http_response, enc_message, enc_message_size);
                free(http_response);
                return ret;
            }
            
            char* invalid_char;
            server_error_t error = (server_error_t)strtoul(http_response, &invalid_char, 10);
            if(*invalid_char != 0) {
                free(http_response);
                return (int)print_error_message(INVALID_ERROR_CODE_FORMAT_ERROR);
            }
            free(http_response);
            return (int)print_error_message(error);

        } else {
            err = res.error();
            printf("Error %d\n", (int)err);
            return (int)print_error_message(HTTP_SEND_ERROR);
        }
    }

    return 0;
}

int client_query(uint8_t* key, uint8_t* data, uint32_t data_index, char* command, uint32_t* data_size)
{ 
    // Encrypt pk
    uint32_t enc_pk_size = 8+12+16;
    uint8_t* enc_pk = (uint8_t*)malloc(enc_pk_size);
    sample_status_t ret = encrypt_data(key, enc_pk, &enc_pk_size, (uint8_t*)CLIENT_ID, 8);
    if(ret != SAMPLE_SUCCESS) {
        free(enc_pk);
        printf("Error code: %d\n", (int)ret);
        return (int)print_error_message(CLIENT_ENCRYPTION_ERROR);
    }

    // Send message for quering
    //uint8_t *enc_message = (uint8_t*)malloc(MAX_ENC_DATA_SIZE*sizeof(uint8_t));
    uint32_t enc_message_size = MAX_ENC_DATA_SIZE;
    uint8_t* enc_message = (uint8_t*)malloc(MAX_ENC_DATA_SIZE*sizeof(uint8_t));
    
    int query_ret = send_query_message(data_index, enc_message, &enc_message_size, command, (uint32_t)strlen(command), enc_pk);
    free(enc_pk);
    if(query_ret) {
        free(enc_message);
        return query_ret;
    }

    // Decrypt received data
    ret = decrypt_data(key, enc_message, enc_message_size, data, data_size);
    free(enc_message);
    if(ret != SAMPLE_SUCCESS) {
        printf("Error code: %d\n", (int)ret);
        return print_error_message(CLIENT_DECRYPTION_ERROR);
    }

    return 0;
}