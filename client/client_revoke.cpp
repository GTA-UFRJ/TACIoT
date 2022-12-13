/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Description: send message revoking some data
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
#include "utils.h"
#include "client_revoke.h"
#include "config_macros.h"
#include HTTPLIB_PATH

int send_revoke_message(uint32_t data_index, char* command, uint32_t command_size, uint8_t* enc_pk, char* id)
{
    // Replace SPACE character in command by "_"
    for(unsigned i=0; i<strlen(command); i++) 
        command[i] = (command[i] == ' ') ? '_' : command[i];


    // Build revoke message
    // http://localhost:7778/revoke/size=24/pk|72d41281|index|000000
    char http_request[URL_MAX_SIZE];
    char http_response[URL_MAX_SIZE];
    uint32_t message_size = 53+(uint32_t)strlen(command)+(8+16+12)*3;
    sprintf(http_request, "/revoke/size=%u/pk|%s|index|%06u|size|%02x|command|%s|encrypted|", 
    message_size, id, data_index, command_size, command);

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
        if (auto res = cli.Get(http_request)) {

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

                printf("Received: Accepted\n");
            }

        } else {
            err = res.error();
            printf("Failed to send HTTP message: error %d\n", (int)err);
            return -1;
        }
    }

    return 0;
}

int client_revoke(uint8_t* key, uint32_t data_index, char* command, char* id)
{
    // Encrypt pk 
    uint32_t enc_pk_size = 8+12+16;
    uint8_t enc_pk[enc_pk_size];
    sample_status_t ret = encrypt_data(key, enc_pk, &enc_pk_size, (uint8_t*)id, 8);
    if(ret != SAMPLE_SUCCESS) {
        printf("\nError encrypting pk. Error code: %d\n", (int)ret);
        return -1;
    }

    // Send message for revocation
    if(send_revoke_message(data_index, command, (uint32_t)strlen(command), enc_pk, id) != 0) 
        return -1;

    return 0;
}