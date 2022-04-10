/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Description: send data for publishing
 */

#include <cstdio>
#include <stdlib.h>
#include <iostream>
#include <string.h>
#include <stdio.h>
#include <chrono>
#include <thread>

#include "client_publish.h"
#include "encryption.h"

#include "sample_libcrypto.h"   
#include "config_macros.h"      
#include "ecp.h"              
#include HTTPLIB_PATH

void send_data_for_publishing(uint8_t* encMessage, uint32_t encMessageLen, char* data_type, uint32_t data_type_size)
{
    size_t header_size = 3+9+5+data_type_size+6+3+10;
    size_t snd_msg_size = (header_size+1)*sizeof(char)+(6*encMessageLen)*sizeof(char);
    char* snd_msg = (char*)malloc(snd_msg_size);
    sprintf(snd_msg, "pk|%s|type|%s|size|%02x|encrypted|", CLIENT_ID, data_type, (unsigned int)encMessageLen);
    char auxiliar[7];
    for (int i=0; i<int(encMessageLen); i++)
    {
        sprintf(auxiliar, "0x%02x--",encMessage[i]);
        snd_msg[header_size+6*i] = auxiliar[0];
        snd_msg[header_size+6*i+1] = auxiliar[1];
        snd_msg[header_size+6*i+2] = auxiliar[2];
        snd_msg[header_size+6*i+3] = auxiliar[3];
        snd_msg[header_size+6*i+4] = auxiliar[4];
        snd_msg[header_size+6*i+5] = auxiliar[5];
    }
    snd_msg[snd_msg_size] = '\0';

    char http_message[URL_MAX_SIZE];
    httplib::Error err = httplib::Error::Success;
    sprintf(http_message, "/publish/size=%d/%s", (int)snd_msg_size, snd_msg);
    printf("%s\n", http_message);

    httplib::Client cli(SERVER_URL, COMUNICATION_PORT_2);
    std::this_thread::sleep_for(std::chrono::milliseconds(LATENCY_MS));
    if (auto res = cli.Get(http_message)) {
        printf("Client sent %s to server\n", http_message);
        if (res->status == 200) {
            fprintf(stdout,"\n%s\n",res->body.c_str());
            printf("Success: received 200 from server\n");
        }
    } else {
        err = res.error();
        printf("Failed: error %d\n", (int)err);
    }
    free(snd_msg);
}

int client_publish(uint8_t* client_data, uint32_t client_data_size, char* data_type, uint32_t data_type_size)
{
    // Data and size must be parametes passed by access point software
    // pk|72d41281|type|weg_multimeter|payload|250110090|permission1|72d41281
    sample_status_t ret;
    size_t encMessageLen;
    uint8_t* encMessage = (uint8_t *) malloc(MAX_ENC_DATA_SIZE*sizeof(uint8_t));;
    ret = encrypt_data (&encMessageLen, encMessage, client_data, client_data_size);

    // Send data for publishing
    send_data_for_publishing(encMessage, encMessageLen, data_type, data_type_size);
    free(encMessage);
    
    return 0;
}
