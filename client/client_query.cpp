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
#include <encryption.h>

#include "client_query.h"
#include "config_macros.h"
#include HTTPLIB_PATH

uint32_t parse_server_response(char* msg, uint8_t* encrypted)
{
    // size|0x%02x|data|
    //uint32_t index;
    uint32_t size;
    char auxiliar[3];
    char* token = strtok_r(msg, "|", &msg);
    int i = 0;
    while (token != NULL)
    {
        i++;
        token = strtok_r(NULL, "|", &msg);
        // Get size
        if (i == 1)
            size = (uint32_t)strtoul(token, NULL, 16);
        // Get encrypted
        if (i == 3)
        {
            encrypted = (uint8_t*)realloc(encrypted,size+1);
            if (encrypted == NULL)
            {
                printf("Allocation error\n");
            }
            for (uint32_t j=0; j<size; j++)
            {
                auxiliar[0] = token[6*j+2];
                auxiliar[1] = token[6*j+3];
                auxiliar[2] = '\0';
                encrypted[j] = (uint8_t)strtoul(auxiliar, NULL, 16);
            }
            encrypted[size] = 0;
        }
    }
    return size;
}

size_t send_query_message(uint32_t data_index, uint8_t* encMessage)
{
    char http_message[URL_MAX_SIZE];
    char http_response[URL_MAX_SIZE];
    httplib::Error err = httplib::Error::Success;
    sprintf(http_message, "/query/size=24/pk|%s|index|%06u", CLIENT_ID, data_index);
    printf("%s\n", http_message);

    uint32_t size = 0;
    httplib::Client cli(SERVER_URL, COMUNICATION_PORT_2);
    std::this_thread::sleep_for(std::chrono::milliseconds(LATENCY_MS));
    if (auto res = cli.Get(http_message)) {
        printf("Client sent %s to server\n", http_message);
        if (res->status == 200) {
            printf("Communication success: received 200 from server\n");
            sprintf(http_response,"%s",res->body.c_str());
            size = parse_server_response(http_response, encMessage);
        }
    } else {
        err = res.error();
        printf("Failed: error %d\n", (int)err);
    }
    return size;
}

int client_query(uint32_t data_index, uint32_t* data_size, uint8_t* data)
{
    // Send message for quering
    uint8_t *encMessage = (uint8_t*)malloc(1024);
    size_t encMessageLen = send_query_message(data_index, encMessage);

    // Decrypt received data
    decrypt_data (encMessageLen, encMessage, data, data_size);
    free(encMessage);

    return 0;
}