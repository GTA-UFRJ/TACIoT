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
#include "timer.h"

#include "client_publish.h"

#include "sample_libcrypto.h"   
#include "config_macros.h"        
#include HTTPLIB_PATH
#include "utils/encryption.h"

int send_data_for_publication(char* pk, char* type, uint8_t* enc_data, uint32_t enc_data_size)
{
    // Build publication message
    // "http://localhost:7778/publish/size=631/pk|72d41281|type|555555|size|62|encrypted|dd-b1-b6-b8-22-d3-9a-76-..."
    size_t header_size = 3+9+5+7+5+3+10;
    size_t snd_msg_size = (header_size+1+3*enc_data_size)*sizeof(char);

    char* snd_msg = (char*)malloc(snd_msg_size);
    sprintf(snd_msg, "pk|%s|type|%s|size|%02x|encrypted|", pk, type, (unsigned int)enc_data_size);

    char auxiliar[4];
    for (uint32_t i=0; i<enc_data_size; i++) {
        sprintf(auxiliar, "%02x-",enc_data[i]);
        memcpy(&snd_msg[header_size+3*i], auxiliar, 3);
    }
    snd_msg[snd_msg_size] = '\0';

    // Build HTTP publication message
    char http_message[URL_MAX_SIZE];
    sprintf(http_message, "/publish/size=%d/%s", (int)snd_msg_size, snd_msg);

    // Send HTTP publication message
    httplib::Error err = httplib::Error::Success;
    httplib::Client cli(SERVER_URL, SERVER_PORT);
    std::this_thread::sleep_for(std::chrono::milliseconds(LATENCY_MS));

    {
        Timer t("communication");
        printf("Sent %s\n",http_message);
        if (auto res = cli.Get(http_message)) {
            
            if (res->status != 200) {
                printf("Server responded with error code: %d\n", (int)res->status);
                free(snd_msg);
                return -1;
            }
            printf("Received: ack\n");

        } else {
            err = res.error();
            printf("Failed HTTP message: error %d\n", (int)err);
            free(snd_msg);
            return -1;
        }
    }
    free(snd_msg);

    return 0;
}

int client_publish(uint8_t* key, client_data_t data)
{
    // Mount text with client data
    // pk|72d41281|type|123456|payload|250|permission1|72d41281
    uint32_t formatted_data_size = 3+9+5+7+8+(uint32_t)strlen(data.payload)+13+8; // 56
    char* formatted_data = (char*)malloc(sizeof(char) * (formatted_data_size+1));
    sprintf(formatted_data,"pk|%s|type|%s|payload|%s|permission1|%s", 
            data.pk, data.type, data.payload, data.permissions_list[0]);

    uint32_t enc_data_size = MAX_ENC_DATA_SIZE;
    uint8_t* enc_data = (uint8_t *) malloc(enc_data_size*sizeof(uint8_t));

    sample_status_t ret = encrypt_data(key, enc_data, &enc_data_size, (uint8_t*)formatted_data, formatted_data_size);
    if(ret != SAMPLE_SUCCESS) {
        printf("\nError encrypting client data. Error code: %d\n", (int)ret);
        free(formatted_data);
        free(enc_data);
        return -1;
    }
    free(formatted_data);

    // Send data for publication
    if(send_data_for_publication(data.pk, data.type, enc_data, enc_data_size) != 0) {
        free(enc_data);
        return -1;
    }
    free(enc_data);
    
    return 0;
}
