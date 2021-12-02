/*
 * Grupo de Teleinformatica e Automacao (GTA, Coppe, UFRJ)
 * Autor: Guilherme Araujo Thomaz
 * Data da ultima modificacao: 30/11/2021
 * Descricao: testes de desenvolvimento
 */

#include <stdio.h>
#include <stdlib.h>
#include "utils.h"
#include "register_client.h"
//#include "request_register.h"
#include "sgx_tcrypto.h"
#include "config_macros.h"

#ifndef CLIENT_PK
#define CLIENT_PK
typedef struct sample_ec_pub_t
{
    uint8_t gx[32];
    uint8_t gy[32];
} sample_ec_pub_t;
#endif

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
    error_code error;
    char client_url[URL_MAX_SIZE];
    sprintf(client_url, "%s:%u", TEST_CLIENT_URL, COMUNICATION_PORT);
    printf("%s\n",client_url);

    // Esta conversao de tipo devera ser feita pelo cliente ou pela comunicacao
    sgx_ec256_public_t* client_public_key;
    client_public_key = (sgx_ec256_public_t*)(&g_sp_pub_key);

    // O cliente comeca enviando estas duas informacoes para o servidor
    error = attest_client(client_url, client_public_key);
    if (error == OK)
    {
        printf("OK\n");
    }
    return int(error);
}

