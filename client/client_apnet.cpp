/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Description: network interface running on access point
 */

#include <stdio.h>
#include <stdlib.h>
#include "config_macros.h"
#include HTTPLIB_PATH
#include "cli.h"
#include "sqlite3.h"
#include "client_permdb_manager.h"
#include "client_publish.h"
#include "client_key_manager.h"
#include "utils.h"
#include "errors.h"

// Secret key for encryption
//uint8_t global_key[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

int initialize_ap_server ()
{
    int ret = 0;
    char return_message [3];
    
    // Access point serves http users devices
    using namespace httplib;
    Server ap_local_server;

    // Receive publication message from sensor
    ap_local_server.Get(R"(/smart-meter=(\d+))", [&](const Request& req, Response& res) {

        if(DEBUG_PRINT) printf("\n---------------------------------------\n");
        if(DEBUG_PRINT) printf("Received update message from smart meter sensor\n");

        // Pick access point ID and CC
        client_identity_t id;
        ret = read_identity(&id);
        if(ret) {
            sprintf(return_message, "%02d", ret);
            res.set_content(return_message, "text/plain");

            return ret;
        }

        // Fill client data structure
        client_data_t data;

        std::string payload_field = req.matches[1].str();
        data.payload = (char*)malloc(payload_field.size()+1);

        sprintf(data.pk, "%s", id.pk);
        sprintf(data.type, "123456");
        sprintf(data.payload, "%s", payload_field.c_str());

        // Pick permissions
        sqlite3 *db;
        if(sqlite3_open(DEFAULT_PERMS_DB_PATH, &db)) {
            printf("SQL error: %s\n", sqlite3_errmsg(db));

            sprintf(return_message, "%02d", (int)OPEN_DATABASE_ERROR);
            res.set_content(return_message, "text/plain");

            return (int)print_error_message(OPEN_DATABASE_ERROR);
        }
        
        data.permissions_list = (char**)malloc(MAX_NUM_PERMISSIONS*sizeof(char*));
        ret = read_default_perms(db, data.type,  data.permissions_list, &data.permissions_count);
        if(ret) {
            free_client_data(data);

            sprintf(return_message, "%02d", ret);
            res.set_content(return_message, "text/plain");

            return ret;
        }

        // Publish data
        ret = client_publish(id.comunication_key, data);
        free_client_data(data);

        // Send response
        sprintf(return_message, "%02d", (int)ret);
        res.set_content(return_message, "text/plain");

        return ret;
    });

    // Receive key configuration message form user equipament
    ap_local_server.Get(R"(/configure-ap-key/size=(\d+)/(.*))", [&](const Request& req, Response& res) {

        if(DEBUG_PRINT) printf("\n---------------------------------------\n");
        if(DEBUG_PRINT) printf("Received key configuration message from user equipament\n");

        // Get message sent in HTTP header
        char* snd_msg = (char*)malloc(URL_MAX_SIZE);

        uint32_t size;
        ret = get_configure_key_message(req, snd_msg, &size);
        if(ret) {
            free(snd_msg);

            sprintf(return_message, "%02d", ret);
            res.set_content(return_message, "text/plain");

            return ret;
        }

        // Parse request
        client_identity_t client_id;
        ret = parse_configure_key_message(snd_msg, &client_id);
        free(snd_msg);
        if(ret) {
            sprintf(return_message, "%02d", ret);
            res.set_content(return_message, "text/plain");

            return ret;
        }

        ret = write_identity(client_id);
        printf("Configured successfully\n");

        // Send response
        sprintf(return_message, "%02d", ret);
        res.set_content(return_message, "text/plain");

        return ret;
    });

    // Receive default access permissions configuration message form user equipament
    ap_local_server.Get(R"(/configure-ap-perms/size=(\d+)/(.*))", [&](const Request& req, Response& res) {

        if(DEBUG_PRINT) printf("\n---------------------------------------\n");
        if(DEBUG_PRINT) printf("Received access permissions configuration message from user equipament\n");

        // Get message sent in HTTP header
        char* snd_msg = (char*)malloc(URL_MAX_SIZE);

        uint32_t size;
        ret = get_configure_perms_message(req, snd_msg, &size);
        if(ret) {
            free(snd_msg);

            sprintf(return_message, "%02d", ret);
            res.set_content(return_message, "text/plain");

            return ret;
        }

        // Parse request
        default_perms_t rcv_perms;
        ret = parse_configure_perms_message(snd_msg, &rcv_perms);
        free(snd_msg);
        if(ret) {
            free_permissions_array(rcv_perms.permissions_list, rcv_perms.permissions_count);

            sprintf(return_message, "%02d", ret);
            res.set_content(return_message, "text/plain");

            return ret;
        }

        // Open deafult access permissions database
        sqlite3 *db;

        if(sqlite3_open(DEFAULT_PERMS_DB_PATH, &db)) {
            printf("SQL error: %s\n", sqlite3_errmsg(db));

            sprintf(return_message, "%02d", (int)OPEN_DATABASE_ERROR);
            res.set_content(return_message, "text/plain");

            return (int)print_error_message(OPEN_DATABASE_ERROR);
        } 

        // Write access permissions for type in database
        ret = write_default_perms(db, rcv_perms.type, rcv_perms.permissions_list, rcv_perms.permissions_count);
        free_permissions_array(rcv_perms.permissions_list, rcv_perms.permissions_count);

        // Send response
        sprintf(return_message, "%02d", (int)ret);
        res.set_content(return_message, "text/plain");

        return ret;
    });

    ap_local_server.Get(R"(/read-ap-perms/size=(\d+)/(.*))", [&](const Request& req, Response& res) {

        if(DEBUG_PRINT) printf("\n---------------------------------------\n");
        if(DEBUG_PRINT) printf("Received access permissions query message from user equipament\n");

        // Get message sent in HTTP header
        char* snd_msg = (char*)malloc(URL_MAX_SIZE);

        uint32_t size;
        ret = get_read_perms_message(req, snd_msg, &size);
        if(ret) {
            free(snd_msg);

            sprintf(return_message, "%02d", (int)ret);
            res.set_content(return_message, "text/plain");

            return ret;
        }

        // Parse request
        char type[7];
        ret = parse_read_perms_message(snd_msg, type);
        free(snd_msg);
        if(ret) {
            sprintf(return_message, "%02d", (int)ret);
            res.set_content(return_message, "text/plain");

            return ret;
        }

        // Open deafult access permissions database
        sqlite3 *db;

        if(sqlite3_open(DEFAULT_PERMS_DB_PATH, &db)) {
            printf("SQL error: %s\n", sqlite3_errmsg(db));

            sprintf(return_message, "%02d", (int)OPEN_DATABASE_ERROR);
            res.set_content(return_message, "text/plain");

            return (int)print_error_message(OPEN_DATABASE_ERROR);
        } 

        // Write access permissions for type in database
        char** permissions = (char**)malloc(MAX_NUM_PERMISSIONS*sizeof(char*));
        uint32_t permissions_count;
        ret = read_default_perms(db, type, permissions, &permissions_count);
        if(ret) {
            free_permissions_array(permissions, permissions_count);

            sprintf(return_message, "%02d", (int)ret);
            res.set_content(return_message, "text/plain");

            return ret;
        }

        char* response = (char*)malloc(permissions_count*9);
        ret = make_perms_response(permissions, permissions_count, response);
        free_permissions_array(permissions, permissions_count);
        if(ret) {
            sprintf(return_message, "%02d", (int)ret);
            res.set_content(return_message, "text/plain");
            
            return ret;
        }

        // Send response
        res.set_content(response, "text/plain");
        return 0;
    });

    ap_local_server.listen(AP_URL, AP_PORT);
    printf("\n");    
    return 0;
}