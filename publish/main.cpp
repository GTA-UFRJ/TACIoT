/*
 * Grupo de Teleinformatica e Automacao (GTA, Coppe, UFRJ)
 * Autor: Guilherme Araujo Thomaz
 * Data da ultima modificacao: 23/12/2021
 * Descrição: processa em enclave o dado do cliente antes da publicacao
 */

#include <cstdio>
#include <stdlib.h>
#include <iostream>
#include <string.h>
#include <stdio.h>
#include <chrono>
#include <thread>
/*
int main()
{
    printf("teste\n");
    return 0;
}
*/

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
uint8_t fabricated_data[142] = {0x70, 0x6b, 0x7c, 0x37, 0x32, 0x64, 0x34, 0x31, 0x32, 
                                0x38, 0x31, 0x7c, 0x73, 0x69, 0x7a, 0x65, 0x7c, 0x37, 
                                0x32, 0x7c, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 
                                0x65, 0x64, 0x7c, 0x97, 0x7b, 0xa3, 0x9e, 0x6c, 0x32, 
                                0x29, 0x40, 0xda, 0xe2, 0x35, 0x89, 0xb0, 0x4c, 0x53, 
                                0xe9, 0x30, 0x37, 0x38, 0x36, 0x33, 0x32, 0x31, 0x33, 
                                0x34, 0x34, 0x32, 0x38, 0x24, 0x4f, 0x52, 0xbf, 0x2e, 
                                0x28, 0xae, 0xa7, 0x41, 0x10, 0x28, 0x42, 0xe6, 0xd4, 
                                0xd3, 0xb3, 0xeb, 0x27, 0x64, 0x47, 0xa5, 0x40, 0x29, 
                                0x5f, 0xc5, 0x9b, 0x05, 0x9d, 0x15, 0xe4, 0x62, 0x74, 
                                0x77, 0x4f, 0x4f, 0x1f, 0x3e, 0xb0, 0xc2, 0x64, 0x34, 
                                0x8e, 0x6d, 0xb4, 0x9c, 0x78, 0x27, 0x0d, 0x14, 0x7f, 
                                0xb3, 0xbc, 0x53, 0x55, 0xb8, 0xb7, 0x89, 0x9f, 0x70, 
                                0x8a, 0x3d, 0x8a, 0x72, 0x35, 0xb2, 0x2b, 0x12, 0x5d, 
                                0xbf, 0x7b, 0x3c, 0x36, 0x62, 0x89, 0x18, 0xda, 0xa6, 
                                0xf3, 0xd6, 0x17, 0x79, 0xc2, 0x90, 0x80};
// uint8_t iv[12];

// Estrutura da mensagem do ponto de acesso
typedef struct iot_message_t
{
    char pk[9];
    char* type;
    uint8_t* processed;
    char* encrypted;
    uint32_t encrypted_size;
} iot_message_t;

// Interface para enclave imprimir segredo usando OCALL (INSEGURA! Apenas para testes)
void ocall_print_secret(uint8_t* secret, uint32_t secret_size)
{
    uint32_t i;
    char hex_number[5];
    for (i=0;i<secret_size;i++)
    {
        sprintf(hex_number, "%x", secret[i]);
        printf("%s ", hex_number);
    }
    printf("\n");
}

int main(int argc, char const *argv[])
{
    // Mede instante de tempo antes
    std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();

    // Cliente criptografa dado com chave secreta
    // pk|72d41281|type|weg_multimeter|payload|250110090|permission1|72d41281
    sample_status_t ret;
    size_t encMessageLen = (SAMPLE_AESGCM_MAC_SIZE + SAMPLE_AESGCM_IV_SIZE + ULTRALIGHT_SIZE-1);
    unsigned char *encMessage = (unsigned char *) malloc((encMessageLen+1)*sizeof(unsigned char));
    const sample_aes_gcm_128bit_key_t (*key)[16];
    key = &sha_key;
    utility_encrypt_file((unsigned char*)ULTRALIGHT_SAMPLE, (size_t)ULTRALIGHT_SIZE, encMessage, encMessageLen, key);
    encMessage[encMessageLen] = '\0';

    // Cliente monta mensagem
    char* snd_msg = (char*)malloc(28*sizeof(char)+(encMessageLen+1)*sizeof(char));
    sprintf(snd_msg, "pk|72d41281|size|%02x|encrypted|%s", (unsigned int)encMessageLen+1 ,encMessage);
    free(encMessage);
    printf("\n");
    /*
    for (int k=0; k<int(28*sizeof(char)+(encMessageLen+1)*sizeof(char)); k++)
    {
        printf("0x%02x, ", (uint8_t)snd_msg[k]);
    }
    printf("\n");
    */
    
    // Latencia de envio
    std::this_thread::sleep_for(std::chrono::milliseconds(LATENCY_MS));

    // Servidor recebe e serpara parametros de acordo com o protocolo Ultralight
    // pk|72d41281|type|weg_multimeter|size|0x35|encrypted|AES128(pk|72d41281|type|weg_multimeter|payload|250110090|permission1|72d41281)    
    iot_message_t rcv_msg;
    char* token = strtok(snd_msg, "|");
    int i = 0;
    while (token != NULL)
    {
        i++;
        token = strtok(NULL, "|");

        // Obtem chave do cliente 
        if (i == 1)
        {
            for (uint32_t j=0; j<9; j++)
            {
                rcv_msg.pk[j] = token[j];
            }
            rcv_msg.pk[9] = '\0';
        }

        // Obtem tamanho da mensagem encriptada
        if (i == 3)
        {
            rcv_msg.encrypted_size = (uint32_t)strtoul(token,NULL,16);
        }
        rcv_msg.encrypted = (char*)malloc(rcv_msg.encrypted_size);

        // Obtem mensagem encriptada
        if (i == 5)
        {
            for (uint32_t j=0; j<rcv_msg.encrypted_size; j++)
            {
                rcv_msg.encrypted[j] = token[j];
            }
            rcv_msg.encrypted[rcv_msg.encrypted_size] = '\0';
        }
    }

    // Se nao  for processar, pula pro final
    if (argc>1)
    {

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

        // Incializa enclave usando sgx_utils
        sgx_enclave_id_t global_eid = 0;
        char token_filename[16];
        sprintf(token_filename, "%s/%s", TOKENS_PATH, rcv_msg.pk);
        //printf("%s",token_filename);
        int sgx_ret = initialize_enclave(&global_eid, token_filename, "server_enclave.signed.so");
        if (sgx_ret<0)
        {
            printf("\nFailed to initialize enclave\n");
            free(sealed_data);
            return 1;
        }

        // Chama enclave para desselar chave, decriptar com a chave, processar e rertornar resultado encriptado
        // pk|72d41281|type|weg_multimeter|size|0x35|encrypted|AES128(pk|72d41281|type|weg_multimeter|payload|250110090|permission1|72d41281)
        unsigned int process = strtoul(argv[1], NULL, 10);
        uint8_t processed_data [RESULT_MAX_SIZE];
        sgx_status_t ecall_status;
        sgx_status_t sgx_status;
        uint32_t real_size;
        uint32_t decMessageLen = rcv_msg.encrypted_size-1 - (SAMPLE_AESGCM_MAC_SIZE + SAMPLE_AESGCM_IV_SIZE);
        sgx_status = process_data(global_eid, &ecall_status,
            (sgx_sealed_data_t*)sealed_data,            //chave selada a ser desselada
            rcv_msg.encrypted,                          //dado a ser decriptado e processado com a chave desselada
            rcv_msg.encrypted_size-1,                   //tamanho do dado encriptado
            decMessageLen,                              //tamanho do vetor alocado com o dado decriptado
            processed_data,                             //dado a ser publicado
            (uint32_t)RESULT_MAX_SIZE,                  //tamanho maximo do buffer com o dado a ser publicado
            &real_size,                                 //tamanho real do dado a ser publicado
            process                                     //nao aplica processamento computacionalmente custoso               
            );
        printf("%s", processed_data);
        printf("\n");
    }

    // Mede o tempo novamente apos o processamento do servidor
    std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
    std::cout << "\nTime difference = " << std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count() << "[us]" << std::endl;

    return 0;
}
