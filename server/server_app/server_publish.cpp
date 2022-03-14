/*
 * Grupo de Teleinformatica e Automacao (GTA, Coppe, UFRJ)
 * Autor: Guilherme Araujo Thomaz
 * Data da ultima modificacao: 11/01/2021
 * Descrição: processa em enclave o dado do cliente antes da publicacao
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
#include HTTPLIB_PATH

#include "sgx_urts.h"
#include "sgx_eid.h"
#include "sgx_ukey_exchange.h"
#include "sgx_uae_epid.h"
#include "sgx_uae_quote_ex.h"
#include "sgx_tcrypto.h"

// Chave compartilhada pelo registro
const sample_aes_gcm_128bit_key_t sha_key[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
const uint8_t client_data[99] = {0xdd, 0xb1, 0xb6, 0xb8, 0x22, 0xd3, 0x9a, 0x76, 0x1c, 
                                 0xb6, 0xc0, 0x30, 0x6a, 0xe9, 0x21, 0x5a, 0x00, 0x00, 
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                                 0x00, 0x73, 0xe3, 0xa6, 0xf9, 0x52, 0xd2, 0x97, 0xa3, 
                                 0xc1, 0x10, 0xf3, 0xc5, 0x05, 0xcb, 0x8e, 0x1d, 0x8b, 
                                 0xe2, 0xcf, 0xcc, 0x16, 0x26, 0x2c, 0x4f, 0x83, 0x94, 
                                 0xe4, 0x9a, 0xe0, 0xee, 0xb3, 0x9c, 0x50, 0x63, 0x68, 
                                 0x4d, 0x21, 0x12, 0xf0, 0xa6, 0x12, 0xbc, 0x86, 0x9d, 
                                 0xe1, 0xa3, 0x9b, 0xd9, 0xf9, 0x31, 0xd2, 0x7c, 0x63, 
                                 0xe3, 0x40, 0x0e, 0x08, 0x17, 0xd3, 0xd2, 0xf8, 0xbf, 
                                 0xbf, 0xc0, 0xee, 0xea, 0x4c, 0xb7, 0x90, 0xdf, 0x00};

// Estrutura da mensagem enviada pelo ponto de acesso (utilizada pelo servidor)
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
    //char hex_number[5]; 
    printf("\n");
    for (i=0;i<secret_size;i++)
    {
        printf("0x%02x, ", secret[i]);
    }
    printf("\n");
}

int main(int argc, char const *argv[])
{
    using namespace httplib;
    Server svr;

    // Incializa enclave usando sgx_utils
    sgx_enclave_id_t global_eid = 0;
    //char token_filename[PATH_MAX_SIZE];
    char* token_filename;
    token_filename = (char*)malloc(PATH_MAX_SIZE*sizeof(char));
    sprintf(token_filename, "%s/%s", TOKENS_PATH, "72d41281");
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
    //printf("Recebi\n");
    char c_size[4];
    uint32_t size;
    char* snd_msg;
    std::string a_size = req.matches[1].str();
    strcpy(c_size, a_size.c_str());
    size = (uint32_t)strtoul(c_size, NULL, 10);

    std::string a_snd_msg = req.matches[2].str();
    snd_msg = (char*)malloc(size*sizeof(char));
    strncpy(snd_msg, a_snd_msg.c_str(), (size_t)(size-1));
    snd_msg[size] = '\0';
    //printf("%s\n", snd_msg);

    // Servidor recebe e serpara parametros de acordo com o protocolo Ultralight
    // type|123456|size|0x35|encrypted|AES128(pk|72d41281|type|weg_multimeter|payload|250110090|permission1|72d41281)    
    iot_message_t rcv_msg;
    char* token = strtok(snd_msg, "|");
    int i = 0;
    char auxiliar[3];
    unsigned long number;
    while (token != NULL)
    {
        i++;
        token = strtok(NULL, "|");
        // Obtem chave do cliente 
        if (i == 1)
        {
            for (uint32_t j=0; j<8; j++)
            {
                rcv_msg.pk[j] = token[j];
            }
            rcv_msg.pk[8] = '\0';
        }
        // Obtem tipo do dado
        if (i == 3)
        {
            for (uint32_t j=0; j<6; j++)
            {
                rcv_msg.type[j] = token[j];
            }
            rcv_msg.type[7] = '\0';
        }
        // Obtem tamanho da mensagem encriptada
        if (i == 5)
        {
            rcv_msg.encrypted_size = (uint32_t)strtoul(token,NULL,16);
        }
        // Obtem mensagem encriptada
        
        if (i == 7)
        {
            rcv_msg.encrypted = (char*)malloc((rcv_msg.encrypted_size+1) * sizeof(char));
            for (uint32_t j=0; j<rcv_msg.encrypted_size; j++)
            {
                auxiliar[0] = token[6*j+2];
                auxiliar[1] = token[6*j+3];
                auxiliar[2] = '\0';
                rcv_msg.encrypted[j] = (char)strtoul(auxiliar, NULL, 16);
                //number = strtoul(auxiliar, NULL, 16);
                //printf("%s, ", auxiliar);
                //printf("%lu, ", number);
                //printf("0x%02x, ", (uint8_t)rcv_msg.encrypted[j]);
            }
            rcv_msg.encrypted[rcv_msg.encrypted_size] = '\0';
            //printf("\n");
        }
    }
    free(snd_msg);

    if (argc < 2){

    // Procura arquivo do usuario e le a chave
    char seal_path[PATH_MAX_SIZE];
    sprintf(seal_path, "%s/%s", SEALS_PATH, rcv_msg.pk);
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

    // printf("%s", rcv_msg.type);
    // Chama enclave para desselar chave, decriptar com a chave, processar e rertornar resultado encriptado
    // type|123456|size|0x35|encrypted|AES128(pk|72d41281|type|weg_multimeter|payload|250110090|permission1|72d41281)
    uint8_t processed_data [RESULT_MAX_SIZE];
    sgx_status_t ecall_status;
    sgx_status_t sgx_status;
    uint32_t real_size;
    uint32_t decMessageLen = rcv_msg.encrypted_size-1 - (SAMPLE_AESGCM_MAC_SIZE + SAMPLE_AESGCM_IV_SIZE);
    char publish_header[5+6+6+4+11+1];
    sprintf(publish_header, "type|%s|size|0x%02x|encrypted|", rcv_msg.type, rcv_msg.encrypted_size);
    char db_path[DB_PATH_SIZE];
    sprintf(db_path, "%s", DB_PATH);
    FILE* db_file = fopen(db_path, "ab");
    if (db_file != NULL) {
        fwrite(publish_header, 1, (size_t)5+6+6+4+11+1, db_file);
    }
    fclose(db_file);
    sgx_status = process_data(global_eid, &ecall_status,
        (sgx_sealed_data_t*)sealed_data,            //chave selada a ser desselada
        rcv_msg.encrypted,                          //dado a ser decriptado com a chave desselada e processado
        rcv_msg.encrypted_size,                     //tamanho do dado encriptado
        decMessageLen,                              //tamanho do vetor alocado com o dado decriptado
        processed_data,                             //dado a ser publicado
        (uint32_t)RESULT_MAX_SIZE,                  //tamanho maximo do buffer com o dado a ser publicado
        &real_size,                                 //tamanho real do dado a ser publicado
        0                                           //nao aplica processamento computacionalmente custoso               
    );
    processed_data[real_size] = '\0';

    // Escreve resultado em BD (cópia em disco, no caso)
    // type|123456|size|0x35|encrypted|AES128(pk|72d41281|type|weg_multimeter|payload|250110090|permission1|72d41281)   
    sprintf(db_path, "%s", DB_PATH);
    db_file = fopen(db_path, "ab");
    if (db_file != NULL) {
        fwrite(processed_data, 1, (size_t)real_size, db_file);
        char nl = '\n';
        fwrite(&nl, 1, sizeof(char), db_file);
    }
    fclose(db_file);
    }
    
    free(rcv_msg.encrypted);
    res.set_content("ack", "text/plain");

    });

    svr.listen(SERVER_URL, COMUNICATION_PORT_2);

    //return 0;
}
