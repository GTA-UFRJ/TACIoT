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

#include "sgx_urts.h"
#include "sgx_eid.h"
#include "sgx_ukey_exchange.h"
#include "sgx_uae_epid.h"
#include "sgx_uae_quote_ex.h"
#include "sgx_tcrypto.h"

// Chave compartilhada pelo registro
const sample_aes_gcm_128bit_key_t sha_key[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

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
    // Dado e tamanho deveriam ser parâmetros passados para o software no ponto de acesso
    // pk|72d41281|type|weg_multimeter|payload|250110090|permission1|72d41281
    sample_status_t ret;
    uint32_t client_data_size = ULTRALIGHT_SIZE; 
    uint8_t client_data[client_data_size];
    for (int i=0; i<client_data_size; i++)
    {
        client_data[i] = (uint8_t)ULTRALIGHT_SAMPLE[i];
    }

    // Dado encriptado:     | MAC | IV | AES128(dado)
    // Tamanho do buffer:     16    12   size(dado)
    // Referência ao MAC:           &dado       : &dado+16
    // Referência ao IV:            &dado+16    : &dado+16+12
    // Referência ao AES128(dado):  &dado+12+16 : 
    size_t encMessageLen = SAMPLE_AESGCM_MAC_SIZE + SAMPLE_AESGCM_IV_SIZE + client_data_size;
    uint8_t *encMessage = (uint8_t *) malloc(encMessageLen*sizeof(uint8_t));
    const sample_aes_gcm_128bit_key_t (*key)[16];
    key = &sha_key;

    // Gera nonce (vetor de inicialização - IV)
    uint8_t iv[12];
    srand(time(NULL));
    for(int i=0;i<12;i++)
    {
        //iv[i] = static_cast<uint8_t>(rand()%10) + 48;
        iv[i] = 0;
    }
    memcpy(encMessage + SAMPLE_AESGCM_MAC_SIZE, iv, SAMPLE_AESGCM_IV_SIZE);

    // Cliente criptografa dado com chave secreta
    ret = sample_rijndael128GCM_encrypt(
        *key,                                                           // Chave de 128 bits = 16 bytes 
        client_data, client_data_size,                                  // Origem + tamanho da origem
        encMessage + SAMPLE_AESGCM_MAC_SIZE + SAMPLE_AESGCM_IV_SIZE,    // AES128(origem)
        iv, SAMPLE_AESGCM_IV_SIZE,                                      // IV + tamanho do Iv
        NULL, 0, (sample_aes_gcm_128bit_tag_t *) (encMessage));         // MAC 
    if(ret == SAMPLE_SUCCESS) printf("ENCRYPT RESULT: SAMPLE_SUCCESS");
    if(ret == SAMPLE_ERROR_INVALID_PARAMETER) printf("ENCRYPT RESULT: SAMPLE_ERROR_INVALID_PARAMETER");
    if(ret == SAMPLE_ERROR_OUT_OF_MEMORY) printf("ENCRYPT RESULT: SAMPLE_ERROR_OUT_OF_MEMORY");
    if(ret == SAMPLE_ERROR_UNEXPECTED) printf("ENCRYPT RESULT: SAMPLE_ERROR_UNEXPECTED");

    // Monta mensagem enviada
    size_t snd_msg_size = 42*sizeof(char)+(encMessageLen+1)*sizeof(char);
    char* snd_msg = (char*)malloc(snd_msg_size);
    sprintf(snd_msg, "pk|72d41281|type|123456|size|%02x|encrypted|", (unsigned int)encMessageLen+1);
    printf("\n");
    for (int i=0; i<int(encMessageLen+1); i++)
    {
        //printf("0x%02x, ",encMessage[i]);
        snd_msg[42+i] = (char)encMessage[i];
    }
    snd_msg[snd_msg_size] = '\0';
    printf("\n");
    free(encMessage);

    // Aplica latencia de envio e mede instante de tempo antes
    std::this_thread::sleep_for(std::chrono::milliseconds(LATENCY_MS));
    std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();

    // Servidor recebe e serpara parametros de acordo com o protocolo Ultralight
    // type|123456|size|0x35|encrypted|AES128(pk|72d41281|type|weg_multimeter|payload|250110090|permission1|72d41281)    
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
            rcv_msg.encrypted = (char*)malloc(rcv_msg.encrypted_size);
        }
        // Obtem mensagem encriptada
        if (i == 7)
        {
            for (uint32_t j=0; j<rcv_msg.encrypted_size; j++)
            {
                rcv_msg.encrypted[j] = token[j];
            }
            rcv_msg.encrypted[rcv_msg.encrypted_size] = '\0';
        }
    }

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
    char token_filename[PATH_MAX_SIZE];
    sprintf(token_filename, "%s/%s", TOKENS_PATH, rcv_msg.pk);
    int sgx_ret = initialize_enclave(&global_eid, token_filename, "server_enclave.signed.so");
    if (sgx_ret<0)
    {
        printf("\nFailed to initialize enclave\n");
        free(sealed_data);
        return 1;
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
        rcv_msg.encrypted_size-1,                   //tamanho do dado encriptado
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

    // Mede o tempo novamente apos o processamento do servidor
    std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
    //std::cout << "\nTime difference = " << std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count() << "[us]" << std::endl;

    return 0;
}
