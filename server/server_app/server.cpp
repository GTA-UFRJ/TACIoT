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
#include "timer.h"

#include "utils.h"
#include "utils_sgx.h"
#include "register_client.h"
#include "server_publish.h"
#include "server_query.h"
#include "sgx_tcrypto.h"
#include "config_macros.h"
#include HTTPLIB_PATH
#include "server.h"

int start_attestation_client ()
{
    char client_url[URL_MAX_SIZE];
    error_code error = OK;
    sprintf(client_url, "%s:%u", TEST_CLIENT_URL, COMUNICATION_PORT);

    // Call function to attest and register client
    error = attest_client(client_url, (sgx_ec256_public_t*)(&g_sp_pub_key));

    // Finalize procedure
    httplib::Client cli(TEST_CLIENT_URL, COMUNICATION_PORT);
    if (auto res = cli.Get("/stop")) {
        if (res->status == 200) {
            std::cout << res->body << std::endl;
        }
    } else {
        //httplib::Error err = httplib::Error::Success;
        res.error();
        printf("%d\n", (int)res.error());
    }

    return int(error);
}

int main (int argc, char** argv)
{
    unsigned concurrentRequestsCount = 0;

    using namespace httplib;
    Server svr;

    // Select beetween secure or insecure modes
    if (argc < 2){
        fprintf(stderr, "Insuficient arguments\n");
        return -1;
    }
    bool secure;
    *argv[1]=='i' ? secure=false : secure=true;  

    // Initialize enclave
    
    sgx_enclave_id_t global_eid = 0;
    char* token_filename;
    token_filename = (char*)malloc(PATH_MAX_SIZE*sizeof(char));
    sprintf(token_filename, "%s/%s", TOKENS_PATH, TOKEN_NAME);
    char enclave_name[25];
    std::string s = "server_enclave.signed.so";
    strcpy(enclave_name, s.c_str());
    int sgx_ret = initialize_enclave(&global_eid, token_filename, enclave_name);
    if (sgx_ret<0)
    {
        printf("\nFailed to initialize enclave\n");
    }
    free(token_filename);

    svr.Get(R"(/publish/size=(\d+)/(.*))", [&](const Request& req, Response& res) {
        // Apply send latency and publish data
        std::this_thread::sleep_for(std::chrono::milliseconds(LATENCY_MS));
        concurrentRequestsCount++;
        //printf("\nCONCURRENT PUBLISH COUNT: %u\n", concurrentRequestsCount);
        if(server_publish(secure, req, res, global_eid))
            return -1;
        concurrentRequestsCount--;
        return 0;
    });

    svr.Get(R"(/query/size=(\d+)/(.*))", [&](const Request& req, Response& res) {
        // Apply send latency and publish data
        std::this_thread::sleep_for(std::chrono::milliseconds(LATENCY_MS));
        concurrentRequestsCount++;
        //printf("\nCONCURRENT QUERY COUNT: %u\n", concurrentRequestsCount);
        if(server_query(secure, req, res, global_eid))
            return -1;
        concurrentRequestsCount--;
        return 0;
    });

    svr.Get(R"(/stop_test)", [&](const Request& req, Response& res) {
        svr.stop();
    });

    if (*argv[1] == 'r') {
        if(start_attestation_client())
            return -1;
    }
    else
    { 
        svr.listen(SERVER_URL, COMUNICATION_PORT_2);
    }
    printf("\n");
    Timer::print_times();
}

