/*
 * Grupo de Teleinformatica e Automacao (GTA, Coppe, UFRJ)
 * Autor: Guilherme Araujo Thomaz
 * Data da ultima modificacao: 23/12/2021
 * Descricao: funcoes do enclave do servidor
 * 
 * Este codigo foi modificado seguindo as permissoes da licenca
 * da Intel Corporation, apresentadas a seguir
 *
 */
/*
 * Copyright (C) 2011-2020 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <assert.h>
#include "server_enclave_t.h"
#include "sgx_tkey_exchange.h"
#include "sgx_tcrypto.h"
#include "sgx_tseal.h"
#include "sgx_trts.h"
//#include "server_processing.h"
#include <string.h>

uint8_t g_secret[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

// Generate context for creating Ga key for Diffie-Hellman Key Exchange
sgx_status_t enclave_init_ra(
    int b_pse,
    sgx_ra_context_t *p_context,
    sgx_ec256_public_t* client_pk)
{
    // isv enclave call to trusted key exchange library.
    sgx_status_t ret;
    ret = sgx_ra_init(client_pk, b_pse, p_context);
    return ret;
}

// End remote attestation discarding key context from memory
sgx_status_t SGXAPI enclave_ra_close(
    sgx_ra_context_t context)
{
    sgx_status_t ret;
    ret = sgx_ra_close(context);
    return ret;
}

// Verify Message Authentication Code (MAC) for ensuring integrity 
sgx_status_t verify_att_result_mac(sgx_ra_context_t context,
                                   uint8_t* p_message,
                                   size_t message_size,
                                   uint8_t* p_mac,
                                   size_t mac_size)
{
    sgx_status_t ret;
    sgx_ec_key_128bit_t mk_key;

    if(mac_size != sizeof(sgx_mac_t))
    {
        ret = SGX_ERROR_INVALID_PARAMETER;
        return ret;
    }
    if(message_size > UINT32_MAX)
    {
        ret = SGX_ERROR_INVALID_PARAMETER;
        return ret;
    }

    do {
        uint8_t mac[SGX_CMAC_MAC_SIZE] = {0};

        ret = sgx_ra_get_keys(context, SGX_RA_KEY_MK, &mk_key);
        if(SGX_SUCCESS != ret)
        {
            break;
        }
        ret = sgx_rijndael128_cmac_msg(&mk_key,
                                       p_message,
                                       (uint32_t)message_size,
                                       &mac);
        if(SGX_SUCCESS != ret)
        {
            break;
        }
        if(0 == consttime_memequal(p_mac, mac, sizeof(mac)))
        {
            ret = SGX_ERROR_MAC_MISMATCH;
            break;
        }

    }
    while(0);

    return ret;
}

// Retrieve cryptographic secrec sent in attestition result
sgx_status_t put_secret_data(
    sgx_ra_context_t context,
    uint8_t *p_secret,
    uint32_t secret_size,
    uint8_t *p_gcm_mac,
    sgx_ec256_public_t* client_pk,
    sgx_sealed_data_t* sealed_data,
    size_t sealed_size)
{
    sgx_status_t ret = SGX_SUCCESS;
    sgx_ec_key_128bit_t sk_key;
    do{
        ret = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);
        if(SGX_SUCCESS != ret)
        {
            break;
        }
        uint8_t aes_gcm_iv[12] = {0};
        ret = sgx_rijndael128GCM_decrypt(&sk_key,
                                        p_secret,
                                        secret_size,
                                        &g_secret[0],
                                        &aes_gcm_iv[0],
                                        12,
                                        NULL,
                                        0,
                                        (const sgx_aes_gcm_128bit_tag_t *)
                                        (p_gcm_mac));
        ocall_print_secret(&g_secret[0], 16);
    } while(0);

    ret = sgx_seal_data(0, NULL, sizeof(g_secret[0])*16, &g_secret[0], (uint32_t)sealed_size, sealed_data);

    // Sealing testing
    /*
    uint8_t plaintext[16] = {0};
    uint32_t plaintext_size = (uint32_t)(16*sizeof(uint8_t));
    ret = sgx_unseal_data(sealed_data, NULL, NULL, &plaintext[0], &plaintext_size);
    ocall_print_secret(&plaintext[0], plaintext_size);
    */

    return ret;
}

// Process data before publishing
sgx_status_t process_data(
    sgx_sealed_data_t* sealed_key,
    uint8_t* encrypted_data,
    uint32_t encrypted_data_size,
    uint32_t dec_msg_len, 
    uint8_t*  processed_result,
    uint32_t buffer_max_size,
    uint32_t* processed_result_size,
    unsigned int process)
{
    // AES128(pk|72d41281|type|weg_multimeter|payload|250110090|permission1|72d41281)
    // Unseal key
    sgx_status_t ret = SGX_SUCCESS;
    uint8_t key[16] = {0}; 
    uint32_t key_size = (uint32_t)(16*sizeof(uint8_t));
    ret = sgx_unseal_data(sealed_key, NULL, NULL, &key[0], &key_size);
    sgx_aes_gcm_128bit_key_t my_key;
    memcpy(my_key, key, (size_t)key_size);
    //ocall_print_secret(&key[0], 16);

    // Decrypt data using key
    uint8_t decMessage [dec_msg_len];
    memset(decMessage, 0, dec_msg_len);
    ret = sgx_rijndael128GCM_decrypt(&my_key,
                                    &encrypted_data[0] + 16 + 12,
                                    dec_msg_len,
                                    &decMessage[0],
                                    &encrypted_data[0] + 16,
                                    12,
                                    NULL,
                                    0,
                                    (const sgx_aes_gcm_128bit_tag_t*)
                                    (&encrypted_data[0]));
    //ocall_print_secret(&decMessage[0], dec_msg_len);

    // Process data
    uint8_t proc[dec_msg_len];
    memcpy(proc, decMessage, sizeof(uint8_t)*dec_msg_len);
    //apply_processing(process, decMessage, dec_msg_len, proc);
    /*
    switch ((proc_code_t)process){
        case none:
        memcpy(proc, decMessage, sizeof(uint8_t)*dec_msg_len);
        break;

        default:
        break;
    }*/
    //*processed_result_size = 12+16+dec_msg_len;

    // Encrypt data using key
    *processed_result_size = (uint32_t)(16 + 12 + sizeof(uint8_t)*(dec_msg_len));
    uint8_t aes_gcm_iv[12] = {0};
    memcpy(processed_result+16, aes_gcm_iv, 12);
    ret = sgx_rijndael128GCM_encrypt(&my_key,
                                    proc,
                                    dec_msg_len,
                                    processed_result + 16 + 12,
                                    &aes_gcm_iv[0],
                                    12,
                                    NULL,
                                    0,
                                    (sgx_aes_gcm_128bit_tag_t*)
                                    (processed_result));
    //ocall_print_secret(&processed_result[0], *processed_result_size);
    processed_result[*processed_result_size] = 0;
    return ret;
}

sgx_status_t retrieve_data(
    sgx_sealed_data_t* sealed_key,
    char* encrypted_data,
    uint32_t encrypted_data_size,
    uint8_t* result)
{
    // Decripta dado recebido do BD/cópia em disco
    sgx_status_t ret = SGX_SUCCESS;
    sgx_aes_gcm_128bit_key_t my_key;
    for (uint32_t i=0; i<16; i++)
    {
        my_key[i] = 0;
    }
    uint8_t encrypted_bytes[encrypted_data_size];
    for (uint32_t j=0; j<encrypted_data_size; j++)
    {
        encrypted_bytes[j] = (uint8_t)encrypted_data[j];
    }
    uint32_t dec_msg_len = encrypted_data_size-12-16;
    uint8_t decMessage [dec_msg_len];
    for (uint32_t i=0; i<dec_msg_len; i++)
    {
        decMessage[i] = 0;
    }
    ret = sgx_rijndael128GCM_decrypt(&my_key,
                                    &encrypted_bytes[0] + 16 + 12,
                                    dec_msg_len,
                                    &decMessage[0],
                                    &encrypted_bytes[0] + 16,
                                    12,
                                    NULL,
                                    0,
                                    (const sgx_aes_gcm_128bit_tag_t*)
                                    (&encrypted_bytes[0]));

    // Dessela chave do cliente requisitor
    uint8_t key[16] = {0}; 
    uint32_t key_size = (uint32_t)(16*sizeof(uint8_t));
    ret = sgx_unseal_data(sealed_key, NULL, NULL, &key[0], &key_size);
    sgx_aes_gcm_128bit_key_t client_key;
    for (uint32_t i=0; i<16; i++)
    {
        client_key[i] = key[i];
    }

    // Encripta dado com a chave do cliente requisitor 
    uint8_t aes_gcm_iv[12] = {0};
    memcpy(result+16, aes_gcm_iv, 12);
    ret = sgx_rijndael128GCM_encrypt(&client_key,
                                    &decMessage[0],
                                    dec_msg_len,
                                    result + 16 + 12,
                                    &aes_gcm_iv[0],
                                    12,
                                    NULL,
                                    0,
                                    (sgx_aes_gcm_128bit_tag_t*)
                                    (result));
    //ocall_print_secret(&result[0], encrypted_data_size);
    return ret;
}
/*
Função secure_aggregation
    tipo = 123456
    char* dados[quantidade_dados]
    int tamanho_dados[qauntidade_dados]
    ocall_read_db_entry(&dados[0], &quantidade_dados[0])
         Aqui dentro a gente faz o seguinte:
         + Abre arquivo BD
         + Loop enquanto ainda nao tiver a quantidade de dados
             + Lê a linha
             + Separa a linha em partes
             + Verifica o tipo
             + Coloca o dado encriptado na lista 
             + coloca tamanho do dado em outra lista
             + Incrementa quantidade de dados
             + Incrementa linha
             + Se terminou arquivo, quantidade de dados acabou
         + Fecha arquivo BD
    Loop na lista com dados encriptados
        Verifica tamanho na lista de tamanhos 
        Decripta dado
        Acumula soma
    Monta mensagem a ser armazenada no BD
    Copia mensagem para o proc
*/