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
#include "errors.h"
#include HTTPLIB_PATH

using namespace httplib;

// pk|72d41281|ck|00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00- (16 bytes of zeros, for example) 
server_error_t parse_register(char* msg, register_message_t* p_rcv_msg)
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

            if(DEBUG_PRINT) printf("pk: %s\n", p_rcv_msg->pk);
        }

        // Get communication key
        if (i == 3) {

            if(DEBUG_PRINT) printf("ck: ");

            char* invalid_char;
            for (uint32_t j=0; j<16; j++){
                auxiliar[0] = token[3*j];
                auxiliar[1] = token[3*j+1];
                auxiliar[2] = '\0';
                p_rcv_msg->ck[j] = (uint8_t)strtoul(auxiliar, &invalid_char, 16);

                if(auxiliar != 0 && *invalid_char != 0) 
                    return print_error_message(INVALID_REGISTRATION_KEY_FIELD_ERROR);

                if(DEBUG_PRINT) printf("%02x,", (unsigned)p_rcv_msg->ck[j]);
            }
            if(DEBUG_PRINT) printf("\n");
        }
    }

    return OK;
}

server_error_t get_register_message(const Request& req, char* snd_msg, uint32_t* p_size)
{
    Timer t("get_register_message");
    if(DEBUG_PRINT) printf("\nGetting register message fields:\n");

    std::string size_field = req.matches[1].str();

    try {
        *p_size = (uint32_t)std::stoul(size_field);
    }
    catch (std::invalid_argument& exception) {
        return print_error_message(INVALID_HTTP_MESSAGE_SIZE_FIELD_ERROR);
    }

    if(*p_size > URL_MAX_SIZE) 
        return print_error_message(HTTP_MESSAGE_SIZE_OVERFLOW_ERROR);

    if(DEBUG_PRINT) printf("Size: %u\n", *p_size);

    std::string message_field = req.matches[2].str();

    strncpy(snd_msg, message_field.c_str(), (size_t)(*p_size-1));
    snd_msg[*p_size] = '\0';

    if(DEBUG_PRINT) printf("Message: %s\n", snd_msg);

    return OK;
}

server_error_t enclave_seal_key(register_message_t rcv_msg, sgx_enclave_id_t global_eid, char* path) 
{
    Timer t("enclave_seal_key");

    sgx_status_t sgx_ret = SGX_SUCCESS;

    // Allocate buffer for sealed data
    uint8_t *temp_sealed_buf = (uint8_t *)malloc(SEALED_SIZE);
    memset(temp_sealed_buf,0,SEALED_SIZE);

    // Enter enclave to seal data
    sgx_status_t retval;
    uint32_t real_sealed_size;
    sgx_ret = sealing_data(
            global_eid, 
            &retval, 
            temp_sealed_buf, 
            SEALED_SIZE, 
            &real_sealed_size, 
            rcv_msg.ck, 
            16);
            
    if (sgx_ret != SGX_SUCCESS || retval != SGX_SUCCESS)
    {
        if(sgx_ret == 0x5001) printf("Insuficient result buffer size (query).");
        else if(sgx_ret == 0x5002) printf("Access denied (query).");
        else printf("SGX error code 0x%04x, 0x%04x\n", (int)sgx_ret, (int)retval);
        free(temp_sealed_buf);
        return print_error_message(SEALING_DATA_ENCLAVE_ERROR);
    }

    server_error_t ret = write_key(temp_sealed_buf, real_sealed_size, path);
    free(temp_sealed_buf);
    if(ret)
        return ret;

    return OK;
}

server_error_t server_register(bool secure, const Request& req, Response& res, sgx_enclave_id_t global_eid) 
{
    Timer t("server_register");
    server_error_t ret = OK;

    // Get message sent in HTTP header
    char* snd_msg = (char*)malloc(URL_MAX_SIZE*sizeof(char));;

    uint32_t size;
    if((ret = get_register_message(req, snd_msg, &size))) {
        free(snd_msg);
        return ret;
    }

    // pk|72d41281|ck|00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00- (16 bytes of zeros, for example) 
    register_message_t rcv_msg;
    ret = parse_register(snd_msg, &rcv_msg);
    free(snd_msg);
    if(ret)
        return ret;

    char* path = (char*)malloc(PATH_MAX_SIZE);
    if(secure == false) {
       
        // Build filename for storing client key
        sprintf(path, "%s/%s_i", SEALS_PATH, rcv_msg.pk);

        if(verify_file_existance(path) == true) {
            free(path);
            return print_error_message(ALREDY_REGISTERED_ERROR);
        }

        ret = write_key((uint8_t*)rcv_msg.ck, 16, path);
        free(path);
        if(ret) 
            return ret;
    } 

    // Secure
    else {

        // Build filename for storing client key
        sprintf(path, "%s/%s", SEALS_PATH, rcv_msg.pk);

        if(verify_file_existance(path) == true) {
            free(path);
            return print_error_message(ALREDY_REGISTERED_ERROR);
        }

        // Seal the client key
        ret = enclave_seal_key(rcv_msg, global_eid, path);
        free(path);
        if(ret)
            return ret;
    }
    
    return OK;
}