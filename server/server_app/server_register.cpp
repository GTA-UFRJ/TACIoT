/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Descripton: receive client key and write to disk
 */

#include <stdlib.h>
#include <iostream>
#include <string.h>
#include <string>
#include <stdio.h>
#include <chrono>
#include <thread>
#include "timer.h"
#include <fstream>

#include "server_register.h"
#include "server_disk_manager.h"

#include "config_macros.h"      // ULTRALIGH_SAMPLE
#include "utils_sgx.h"
#include "utils.h"
#include "server_enclave_u.h"
#include HTTPLIB_PATH

using namespace httplib;

// pk|72d41281|ck|00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00- (16 bytes of zeros, for example) 
int parse_register(uint32_t size, char* msg, register_message_t* p_rcv_msg)
{
    Timer t("parse_register");
    
    char* token = strtok_r(msg, "|", &msg);
    int i = 0;
    char auxiliar[3];
    while (token != NULL)
    {
        i++;
        token = strtok_r(NULL, "|", &msg);

        // Get client key
        if (i == 1){
            memcpy(p_rcv_msg->pk, token, 8);
            p_rcv_msg->pk[8] = '\0';
        }

        // Get communication key
        if (i == 3) {

            char* invalid_char;
            for (uint32_t j=0; j<16; j++){
                auxiliar[0] = token[3*j];
                auxiliar[1] = token[3*j+1];
                auxiliar[2] = '\0';
                p_rcv_msg->ck[j] = (uint8_t)strtoul(auxiliar, &invalid_char, 16);

                if(auxiliar != 0 && *invalid_char != 0) {
                    printf("\nInvalid register message format.\n");
                    return -1;
                }
            }
        }
    }

    return 0;
}

int get_register_message(const Request& req, char* snd_msg, uint32_t* p_size)
{
    Timer t("get_register_message");

    std::string size_field = req.matches[1].str();

    try {
        *p_size = (uint32_t)std::stoul(size_field);
    }
    catch (std::invalid_argument& exception) {
        printf("\nFailed to detect HTTP message size\n");
        return -1;
    }

    if(*p_size > URL_MAX_SIZE) {
        printf("\nHTTP message bigger than the maximum size\n");
        return -1;
    }

    std::string message_field = req.matches[2].str();

    strncpy(snd_msg, message_field.c_str(), (size_t)(*p_size-1));
    snd_msg[*p_size] = '\0';

    return 0;
}

int enclave_seal_key(register_message_t rcv_msg, sgx_enclave_id_t global_eid, char* path) 
{
    Timer t("enclave_seal_key");

    sgx_status_t ret = SGX_SUCCESS;

    // Allocate buffer for sealed data
    uint8_t *temp_sealed_buf = (uint8_t *)malloc(SEALED_SIZE);
    if(temp_sealed_buf == NULL) {
        printf("\n(sec) Problem allocating buffer for sealing\n");
        return -1;
    }
    memset(temp_sealed_buf,0,SEALED_SIZE);

    // Enter enclave to seal data
    sgx_status_t retval;
    uint32_t real_sealed_size;
    ret = sealing_data(
            global_eid, 
            &retval, 
            temp_sealed_buf, 
            SEALED_SIZE, 
            &real_sealed_size, 
            rcv_msg.ck, 
            16);
            
    if (ret != SGX_SUCCESS || retval != SGX_SUCCESS)
    {
        printf("\n(sec) Enclave problem sealing key\n");
        printf("SGX error codes %d, %d\n", (int)ret, (int)retval);
        free(temp_sealed_buf);
        return -1;
    }

    if(write_key(rcv_msg.pk, temp_sealed_buf, real_sealed_size, path)) {
        return -1;
    }
    free(temp_sealed_buf);

    return 0;
}

int server_register(bool secure, const Request& req, Response& res, sgx_enclave_id_t global_eid) 
{
    Timer t("server_register");

    // Get message sent in HTTP header
    char* snd_msg = (char*)malloc(URL_MAX_SIZE*sizeof(char));;

    uint32_t size;
    if(get_register_message(req, snd_msg, &size)) {
        free(snd_msg);
        return -1;
    }

    // pk|72d41281|ck|00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00- (16 bytes of zeros, for example) 
    register_message_t rcv_msg;
    if(parse_register(size, snd_msg, &rcv_msg))
        return -1;
    free(snd_msg);

    if(secure == false) {
       
        // Build filename for storing client key
        char path[PATH_MAX_SIZE];
        sprintf(path, "%s/%s_i", SEALS_PATH, rcv_msg.pk);

        if(verify_file_existance(path) == true) {
            printf("client key alerfy registered\n");
            res.set_content("client key alerfy registered", "text/plain");
            return -1;
        }

        if(write_key(rcv_msg.pk, (uint8_t*)rcv_msg.ck, 16, path)) {
            printf("registration error\n");
            res.set_content("registration error", "text/plain");
            return -1;
        }
    } 

    // Secure
    else {

        // Build filename for storing client key
        char path[PATH_MAX_SIZE];
        sprintf(path, "%s/%s", SEALS_PATH, rcv_msg.pk);

        if(verify_file_existance(path) == true) {
            printf("client key alerfy registered\n");
            res.set_content("client key alerfy registered", "text/plain");
            return -1;
        }

        // Seal the client key
        if(enclave_seal_key(rcv_msg, global_eid, path)) {
            printf("registration error\n");
            res.set_content("registration error", "text/plain");
            return -1;
        }
    }
    
    res.set_content("ack", "text/plain");
    return 0;
}