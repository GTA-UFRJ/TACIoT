/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Description: network interface for the user equipament to configure the AP
 */

#include <stdlib.h>
#include "client_uenet.h"
#include "config_macros.h"
#include HTTPLIB_PATH
#include "errors.h"

int send_register_ap_message(client_identity_t id) {

    // Build register message
    // pk|72d41281|ck|00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-
    size_t snd_msg_size = 3+9+3+16*3+1;
    char* snd_msg = (char*)malloc(snd_msg_size);
    char ck[3*16+1];
    for(uint32_t index=0; index<16; index++)
        sprintf(ck+3*index, "%02x-", (id.comunication_key)[index]);
    sprintf(snd_msg, "pk|%s|ck|%s", id.pk, ck);

    // Build HTTP register message
    char* http_message = (char*)malloc(URL_MAX_SIZE);
    sprintf(http_message, "/configure-ap-key/size=%d/%s", (int)snd_msg_size, snd_msg);
    free(snd_msg);

    // Send HTTP register ap message
    httplib::Error err = httplib::Error::Success;
    httplib::Client cli(AP_URL, AP_PORT);

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
    
    return 0;
}

int send_read_ap_perms_message(char* type, char* perms) {

    // Build message
    // type|123456
    uint32_t formatted_data_size = 5+6;
    char* formatted_data = (char*)malloc(formatted_data_size+1);
    sprintf(formatted_data,"type|%s", type);

    // Build HTTP permissions message
    char* http_message = (char*)malloc(URL_MAX_SIZE);
    sprintf(http_message, "/read-ap-perms/size=%d/%s", formatted_data_size+1, formatted_data);
    free(formatted_data);


    // Send HTTP permissions message
    httplib::Error err = httplib::Error::Success;
    httplib::Client cli(AP_URL, AP_PORT);

    printf("Sent %s\n", http_message);
    auto res = cli.Get(http_message);
    free(http_message);
    if (res) {
        
        if (res->status != 200) {
            printf("Error code: %d\n", (int)res->status);
            return (int)print_error_message(HTTP_RESPONSE_ERROR);
        }

        for(unsigned i=0; i < (res->body).length(); i++)
            perms[i] = ( (res->body)[i] == ',' ? ' ' : (res->body)[i]);
        perms[(res->body).length()] = '\0';

    } else {
        err = res.error();
        printf("Error %d\n", (int)err);
        return (int)print_error_message(HTTP_SEND_ERROR);
    }



    return 0;
}

int send_write_ap_perms_message(default_perms_t perms) {

    // Build message
    // type|123456|permission1|72d41281|...
    uint32_t formatted_data_size = 5+7+8+(13+8)*(perms.permissions_count); 
    char* formatted_data = (char*)malloc(formatted_data_size+1);
    sprintf(formatted_data,"type|%s", perms.type);

    char* permission = (char*)malloc(22);
    for(uint32_t index=0; index<perms.permissions_count; index++) {
        sprintf(permission, "|permission%d|%s", index, (perms.permissions_list)[index]);
        strncpy(formatted_data+strlen(formatted_data), permission, strlen(permission));
    }
    free(permission);
    printf("%s\n", formatted_data);

    // Build HTTP permissions message
    char* http_message = (char*)malloc(URL_MAX_SIZE);
    sprintf(http_message, "/configure-ap-perms/size=%d/%s", formatted_data_size+1, formatted_data);
    free(formatted_data);

    // Send HTTP permissions message
    httplib::Error err = httplib::Error::Success;
    httplib::Client cli(AP_URL, AP_PORT);

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

    return 0;
}