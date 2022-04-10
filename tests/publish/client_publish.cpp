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
#include "ecp.h"                // sample_ec_key_128bit_t

// Chave compartilhada pelo registro
const sample_aes_gcm_128bit_key_t sha_key[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

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

    // Monta mensagem enviada (aqui entraria HTTP)
    size_t snd_msg_size = 42*sizeof(char)+(encMessageLen+1)*sizeof(char);
    char* snd_msg = (char*)malloc(snd_msg_size);
    sprintf(snd_msg, "pk|72d41281|type|123456|size|%02x|encrypted|", (unsigned int)encMessageLen+1);
    printf("\n");
    /*for (int i=0; i<int(encMessageLen+1); i++)
    {
        printf("0x%02x, ",encMessage[i]);
        snd_msg[42+i] = (char)encMessage[i];
    }*/
    snd_msg[snd_msg_size] = '\0';
    printf("\n");
    free(encMessage);
    
/*
    char key_path[20];
    sprintf(key_path, "insecure_key_file");
    FILE* key_file = fopen(key_path, "ab");
    if (key_file != NULL) {
        fwrite(sha_key, 1, 16, key_file);
        char nl = '\n';
        fwrite(&nl, 1, 1, key_file);
    }
    fclose(key_file);
  */  
    return 0;
}
