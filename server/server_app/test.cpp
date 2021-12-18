/*
 * Grupo de Teleinformatica e Automacao (GTA, Coppe, UFRJ)
 * Autor: Guilherme Araujo Thomaz
 * Data da ultima modificacao: 15/12/2021
 * Descricao: testes de desenvolvimento
 */

#include <stdio.h>
#include <stdlib.h>
#include "utils.h"
#include "register_client.h"
//#include "request_register.h"
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

int main ()
{
    char client_url[URL_MAX_SIZE];
    //sprintf(client_url, "%s:%u", TEST_CLIENT_URL, COMUNICATION_PORT);
    //printf("%s\n",client_url);
    //sgx_ec256_public_t* client_public_key;
    //client_public_key = (sgx_ec256_public_t*)(&g_sp_pub_key);
    error_code error = OK;
    //char c_pk[16*4*2+1];
    //sample_ec_pub_t g_cli_pk;
/*
    // Configura mensagem de iniciar atestacao do servidor
    using namespace httplib;
    Server svr;
    //msg_t received_msg;
    svr.Get(R"(/register/url=([0-9a-zA-Z@]+)&port=(\d+)&pk=([0-9a-f]+))", [&](const Request& req, Response& res) {
        
        // Responde "ok" para o cliente
        fprintf(stdout,"\nServidor Recebeu\n");
        fprintf(stdout,"\nServidor enviou: ok\n");
        res.set_content("ok", "text/plain");

        // Verifica parametros recebidos na forma de string
        std::string url = req.matches[1].str();
        std::string port = req.matches[2].str();
        std::string a_pk = req.matches[3].str();
        sprintf(client_url,"%s:%s",url.c_str(),port.c_str());
        sprintf(c_pk,"%s",a_pk.c_str());
        fprintf(stdout,"\n%s e %s\n", client_url, c_pk);

        // Monta o par gx e gy do cliente
        char auxiliar[3];
        auxiliar[2] = '\0';
        for (int i=0; i<16*4; i=i+2)
        {
            auxiliar[0] = c_pk[i];
            auxiliar[1] = c_pk[i+1];
            g_cli_pk.gx[i/2] = (uint8_t)strtoul(auxiliar, NULL, 16);
        }
        for (int i=16*4; i<16*4*2; i=i+2)
        {
            auxiliar[0] = c_pk[i];
            auxiliar[1] = c_pk[i+1];
            g_cli_pk.gy[i/2] = (uint8_t)strtoul(auxiliar, NULL, 16);
        }
        //sgx_ec256_public_t* pk;
        //pk = (sgx_ec256_public_t*)(&g_cli_pk);

        // Chama funcao para atestar e registrar o cliente
        error = attest_client(client_url, (sgx_ec256_public_t*)(&g_cli_pk));
    });
*/
    sprintf(client_url, "%s:%u", TEST_CLIENT_URL, COMUNICATION_PORT);

    // Chama funcao para atestar e registrar o cliente
    error = attest_client(client_url, (sgx_ec256_public_t*)(&g_sp_pub_key));

/*
    // Inicializa o servidor ouvindo na porta 7778
    char server_url[URL_MAX_SIZE];
    sprintf(server_url,SERVER_URL);
    const std::string srv_url(server_url);
    svr.listen(server_url, COMUNICATION_PORT_2);
*/
    return int(error);
}

