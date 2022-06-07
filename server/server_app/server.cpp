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

#include "utils.h"
#include "utils_sgx.h"
#include "register_client.h"
#include "server_publish.h"
#include "server_query.h"
#include "sgx_tcrypto.h"
#include "config_macros.h"
#include HTTPLIB_PATH
/*
typedef enum msg_t{
    register,
    put_data
} msg_t;
*/
#ifndef CLIENT_PK
#define CLIENT_PK
typedef struct sample_ec_pub_t
{
    uint8_t gx[32];
    uint8_t gy[32];
} sample_ec_pub_t;
#endif

// Gabarito de chave a ser recebida nos testes
static const sample_ec_pub_t g_sp_pub_key = {
    {
        0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf,
        0x85, 0xd0, 0x3a, 0x62, 0x37, 0x30, 0xae, 0xad,
        0x3e, 0x3d, 0xaa, 0xee, 0x9c, 0x60, 0x73, 0x1d,
        0xb0, 0x5b, 0xe8, 0x62, 0x1c, 0x4b, 0xeb, 0x38
    },
    {
        0xd4, 0x81, 0x40, 0xd9, 0x50, 0xe2, 0x57, 0x7b,
        0x26, 0xee, 0xb7, 0x41, 0xe7, 0xc6, 0x14, 0xe2,
        0x24, 0xb7, 0xbd, 0xc9, 0x03, 0xf2, 0x9a, 0x28,
        0xa8, 0x3c, 0xc8, 0x10, 0x11, 0x14, 0x5e, 0x06
    }
};

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
        httplib::Error err = httplib::Error::Success;
        err = res.error();
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
        printf("\nCONCURRENT PUBLISH COUNT: %u\n", concurrentRequestsCount);
        if(server_publish(secure, req, res, global_eid))
            return -1;
        concurrentRequestsCount--;
    });

    svr.Get(R"(/query/size=(\d+)/(.*))", [&](const Request& req, Response& res) {
        // Apply send latency and publish data
        std::this_thread::sleep_for(std::chrono::milliseconds(LATENCY_MS));
        concurrentRequestsCount++;
        printf("\nCONCURRENT QUERY COUNT: %u\n", concurrentRequestsCount);
        if(server_query(secure, req, res, global_eid))
            return -1;
        concurrentRequestsCount--;
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
}

