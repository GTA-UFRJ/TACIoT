/*
 * Grupo de Teleinformatica e Automacao (GTA, Coppe, UFRJ)
 * Autor: Guilherme Araujo Thomaz
 * Data da ultima modificacao: 11/01/2021
 * Descrição: recebe dado do BD e envia para o cliente
 */

#include <cstdio>
#include <stdlib.h>
#include <iostream>
#include <string.h>
#include <stdio.h>
#include <chrono>
#include <thread>

#include "sample_libcrypto.h"   // sample_aes_gcm_128bit_key_t
#include "config_macros.h"      // ULTRALIGH_SAMPLE
#include "utils_sgx.h"
#include "utils.h"
#include "server_enclave_u.h"
#include "ecp.h"                // sample_ec_key_128bit_t

#include "sgx_urts.h"
#include "sgx_eid.h"
#include "sgx_ukey_exchange.h"
#include "sgx_uae_epid.h"
#include "sgx_uae_quote_ex.h"
#include "sgx_tcrypto.h"

// Chave compartilhada pelo registro
const sample_aes_gcm_128bit_key_t sha_key[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

// Estrutura do dado publicado
typedef struct iot_message_t
{
    char pk[9];
    char type[7];
    uint32_t encrypted_size;
    char* encrypted;
} iot_message_t;

// Interface para enclave imprimir segredo usando OCALL (INSEGURA! Apenas para testes)
void ocall_print_secret(uint8_t* secret, uint32_t secret_size)
{
    uint32_t i;
    char hex_number[5];
    printf("\n");
    for (i=0;i<secret_size;i++)
    {
        printf("0x%02x, ", secret[i]);
    }
    printf("\n");
}

int main(int argc, char const *argv[])
{
    // Mede instante de tempo antes
    std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();

    // Recebe dado encriptado publicado no BD/cópia em disco no índice disk_index
    uint32_t disk_index = 0;
    char* line = NULL;
    char db_path[DB_PATH_SIZE];
    sprintf(db_path, "%s", DB_PATH);
    FILE* db_file = fopen(db_path, "rb");
    if (db_file == NULL)
    {
        printf("Failed opening %s file", db_path);
    }
    fseek(db_file, disk_index, 0);
    char published_header[32];
    fread(published_header,1,32,db_file);
    uint32_t encrypted_size; 

    // Servidor recebe e serpara parametros
    iot_message_t published_msg;
    char* token = strtok(published_header, "|");
    int i = 0;
    while (token != NULL)
    {
        i++;
        token = strtok(NULL, "|");
        // Obtem tipo do dado
        if (i == 1)
        {
            for (uint32_t j=0; j<6; j++)
            {
                published_msg.type[j] = token[j];
            }
            published_msg.type[7] = '\0';
        }
        // Obtem tamanho da mensagem encriptada
        if (i == 3)
        {
            published_msg.encrypted_size = (uint32_t)strtoul(token,NULL,16);
        }
    }

    // Obtem mensagem encriptada
    published_msg.encrypted = (char*)malloc(published_msg.encrypted_size+1);
    fread(published_msg.encrypted,1,published_msg.encrypted_size,db_file);
    published_msg.encrypted[published_msg.encrypted_size] = '\0';
    fclose(db_file);

    // Procura arquivo do usuario e le a chave
    char seal_path[PATH_MAX_SIZE];
    sprintf(seal_path, "%s/%s", SEALS_PATH, "72d41281");
    FILE* seal_file = fopen(seal_path, "rb");
    size_t sealed_size = sizeof(sgx_sealed_data_t) + sizeof(uint8_t)*16;
    uint8_t* sealed_data = (uint8_t*)malloc(sealed_size);
    if (seal_file == NULL) {
        printf("\nWarning: Failed to open the seal file \"%s\".\n", seal_path);
        fclose(seal_file);
        free(sealed_data);
        return 1;
    }
    else {
        fread(sealed_data,1,sealed_size,seal_file);
        fclose(seal_file);
    }

    // Incializa enclave usando sgx_utils
    sgx_enclave_id_t global_eid = 0;
    char token_filename[PATH_MAX_SIZE];
    sprintf(token_filename, "%s/%s", TOKENS_PATH, published_msg.pk);
    int sgx_ret = initialize_enclave(&global_eid, token_filename, "server_enclave.signed.so");
    if (sgx_ret<0)
    {
        printf("\nFailed to initialize enclave\n");
        free(sealed_data);
        return 1;
    }

    // Chama enclave para decriptar dado e encriptar com a chave do cliente 
    sgx_status_t sgx_status;
    sgx_status_t ecall_status;
    uint8_t queried_data[published_msg.encrypted_size];
    sgx_status = retrieve_data(global_eid, &ecall_status,
        (sgx_sealed_data_t*)sealed_data,            //chave selada a ser desselada
        published_msg.encrypted,                    //dado a ser decriptado com a chave desselada e enviado
        published_msg.encrypted_size-1,             //tamanho do dado encriptado
        queried_data                                //dado a ser enviado encriptado com a chave do cliente
    );
    queried_data[published_msg.encrypted_size] = '\0';
    free(published_msg.encrypted);
    printf("\n");
    for (uint8_t j = 0; j < published_msg.encrypted_size; j++)
    {
        printf("0x%02x, ", queried_data[j]);
    }
    printf("\n");
    
    // Latencia de envio
    std::this_thread::sleep_for(std::chrono::milliseconds(LATENCY_MS));
    
    // Mede o tempo novamente apos o envio para o cliente
    std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
    //std::cout << "\nTime difference = " << std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count() << "[us]" << std::endl;

    return 0;
}
