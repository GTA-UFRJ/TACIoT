/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Description: send registration info for the server
 */

#include <cstdio>
#include <stdlib.h>
#include <iostream>
#include <string.h>
#include <stdio.h>
#include <chrono>
#include <thread>
#include "timer.h"
#include "errors.h"

#include "client_register.h"

#include "config_macros.h"        
#include HTTPLIB_PATH


int send_registration(char* snd_msg) {

    // Build HTTP registration message
    char* http_message = (char*)malloc(URL_MAX_SIZE);
    sprintf(http_message, "/register/size=%d/%s", 63, snd_msg);
    free(snd_msg);

    // Send HTTP publication message
    httplib::Error err = httplib::Error::Success;
    httplib::Client cli(SERVER_URL, SERVER_PORT);
    std::this_thread::sleep_for(std::chrono::milliseconds(LATENCY_MS));
    {
        Timer t("communication");

        printf("Sent %s\n", http_message);
        auto res = cli.Get(http_message);
        free(http_message);
        if (res) {

            if (res->status != 200) {
                printf("Error code: %d\n", (int)res->status);
                return (int)print_error_message(HTTP_RESPONSE_ERROR);
            }

            char* http_response = (char*)malloc(URL_MAX_SIZE);
            sprintf(http_response,"%s",res->body.c_str());
            if(!strcmp(http_response, "0")) {
                printf("Received ack\n");
                free(http_response);
                return 0;
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


int client_register(client_identity_t rcv_id) {

    // Build message    
    // pk|72d41281|ck|00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00- (16 bytes of zeros, for example) 
    uint32_t formatted_msg_size = 62;
    char* formatted_msg = (char*)malloc(formatted_msg_size+1);
    sprintf(formatted_msg,"pk|%s|ck|", rcv_id.pk);

    for(uint32_t index=0; index<16; index++) 
        sprintf(formatted_msg+strlen(formatted_msg), "%02x-", rcv_id.comunication_key[index]);
    printf("%s\n", formatted_msg);

    // Send message to server
    int ret = send_registration(formatted_msg);
    return ret;
}