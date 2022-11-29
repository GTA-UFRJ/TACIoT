/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Descripton: serve client messages and register client
 */

#include <stdio.h>
#include <stdlib.h>
#include <chrono>
#include <thread>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include "errors.h"
#include "timer.h"
#include "utils.h"
#include "utils_sgx.h"
#include "server_publish.h"
#include "server_query.h"
#include "server_register.h"
#include "server_revoke.h" 
#include "sgx_tcrypto.h"
#include "config_macros.h"
#include HTTPLIB_PATH
#include "server.h"

void signal_handler (int sigNumber) 
{
    if(sigNumber == SIGTERM || sigNumber == SIGINT) {
        Timer::print_times();
        exit(0);
    }
}

int main (int argc, char** argv)
{
    // Activate handler for process termination and interruption signals
    if(signal(SIGTERM, signal_handler) == SIG_ERR || signal(SIGINT, signal_handler) == SIG_ERR) 
        printf("WARNING: signals not treated as expected\n");

    using namespace httplib;
    Server svr;

    // Select beetween secure or insecure modes
    if (argc < 2)
        return print_error_message(INIT_ERROR);

    bool secure = (*argv[1]=='i' ? false : true);  

    if(DEBUG == true) printf("---------------------------------------\nInitialized server ");
    if(DEBUG == true) secure ? printf("(secure mode)\n") : printf("(insecure mode)\n");

    // Initialize database
    /* if(configure_database()) {
     *   printf("Problem configuring database\n");
     *   return -1;
     * }
     */
    
    // Initialize enclave
    char* token_filename = (char*)malloc(PATH_MAX_SIZE);
    sprintf(token_filename, "%s/%s", TOKENS_PATH, TOKEN_NAME);
    
    sgx_enclave_id_t global_eid = 0;

    char* enclave_name = (char*)malloc(25);
    std::string s(ENCLAVE_PATH);
    strcpy(enclave_name, s.c_str());

    int sgx_ret = initialize_enclave(&global_eid, token_filename, enclave_name);
    free(token_filename);
    free(enclave_name);
    if (sgx_ret<0)
        return print_error_message(ENCALVE_INIT_ERROR);

    if(DEBUG == true) printf("Initialized enclave\n");

    svr.Get(R"(/publish/size=(\d+)/(.*))", [&](const Request& req, Response& res) {

        // Simulate latency 
        std::this_thread::sleep_for(std::chrono::milliseconds(LATENCY_MS));

        if(DEBUG) printf("\n---------------------------------------\n");
        if(DEBUG) printf("Received publication message\n");

        server_error_t ret = server_publish(secure, req, res, global_eid);
        if(ret) {
            if(DEBUG) printf("\nSending error message to client\n");

            char return_message [3];
            sprintf(return_message, "%02d", (int)ret);

            res.set_content(return_message, "text/plain");
        }
        return ret;
    });

    svr.Get(R"(/query/size=(\d+)/(.*))", [&](const Request& req, Response& res) { 

        // Simulate latency 
        std::this_thread::sleep_for(std::chrono::milliseconds(LATENCY_MS));
        
        if(DEBUG) printf("\n---------------------------------------\n");
        if(DEBUG) printf("Received query message\n");

        server_error_t ret = server_query(secure, req, res, global_eid);
        if(ret){
            if(DEBUG) printf("\nSending error message\n");

            char return_message [3];
            sprintf(return_message, "%02d", (int)ret);

            res.set_content(return_message, "text/plain");
        }
        return ret;
    });

    svr.Get(R"(/revoke/size=(\d+)/(.*))", [&](const Request& req, Response& res) { 

        // Simulate latency 
        std::this_thread::sleep_for(std::chrono::milliseconds(LATENCY_MS));
        
        if(DEBUG) printf("\n---------------------------------------\n");
        if(DEBUG) printf("Received revocation message\n");

        if(server_error_t ret = server_revoke(secure, req, res, global_eid)){
            if(DEBUG) printf("Sending error message\n");

            char return_message [3];
            sprintf(return_message, "%02d", (int)ret);

            res.set_content(return_message, "text/plain");
            
            return ret;
        }
        return OK;
    });

/*
    svr.Get(R"(/benchmark/secret_code=123456)", [&](const Request& req, Response& res) {
        Timer::print_times();
    });
*/

    svr.Get(R"(/register/size=(\d+)/(.*))", [&](const Request& req, Response& res) { 

        // Simulate latency 
        std::this_thread::sleep_for(std::chrono::milliseconds(LATENCY_MS));
        
        if(server_error_t ret = server_register(secure, req, res, global_eid)){
            if(DEBUG) printf("Sending error message\n");

            char return_message [3];
            sprintf(return_message, "%02d", (int)ret);

            res.set_content(return_message, "text/plain");
            
            return ret;
        }
        return OK;
    });

    svr.listen(SERVER_URL, SERVER_PORT);
    printf("\n");
    return OK;
}

