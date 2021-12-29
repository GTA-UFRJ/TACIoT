/*
 * Grupo de Teleinformatica e Automacao (GTA, Coppe, UFRJ)
 * Autor: Guilherme Araujo Thomaz
 * Data da ultima modificacao: 15/11/2021
 * Descricao: funcoes e tipos auxiliares
 * 
 * Este codigo foi modificado seguindo as permissoes da licenca
 * da Intel Corporation, apresentadas a seguir
 *
 */

#include "utils.h"
#include <string.h>
#include <chrono>
#include "sample_libcrypto.h"

errno_t memcpy_s(
    void *dest,
    size_t numberOfElements,
    const void *src,
    size_t count)
{
    if(numberOfElements<count)
        return -1;
    memcpy(dest, src, count);
    return 0;
}

void PRINT_BYTE_ARRAY(
    FILE *file, void *mem, uint32_t len)
{
    if(!mem || !len)
    {
        fprintf(file, "\n( null )\n");
        return;
    }
    uint8_t *array = (uint8_t *)mem;
    fprintf(file, "%u bytes:\n{\n", len);
    uint32_t i = 0;
    for(i = 0; i < len - 1; i++)
    {
        fprintf(file, "0x%x, ", array[i]);
        if(i % 8 == 7) fprintf(file, "\n");
    }
    fprintf(file, "0x%x ", array[i]);
    fprintf(file, "\n}\n");
}

//uint8_t iv[12];

void gen_iv(uint8_t* iv)
{
    srand(time(NULL));
    for(int i=0;i<12;i++)
    {
        iv[i] = static_cast<uint8_t>(rand()%10) + 48;
        //iv[i] = 0;
    }
}

void utility_encrypt_file(unsigned char *decMessageIn, size_t len, unsigned char *encMessageOut, size_t lenOut, const sample_aes_gcm_128bit_key_t (*key)[16])
{
    uint8_t *origMessage = (uint8_t *) decMessageIn;
    uint8_t p_dst[lenOut];
    sample_status_t ret;

    // Generate the IV (nonce)
    uint8_t iv[12];
    gen_iv(iv);
    memcpy(p_dst + SAMPLE_AESGCM_MAC_SIZE, iv, SAMPLE_AESGCM_IV_SIZE);

    ret = sample_rijndael128GCM_encrypt(
            *key,
            origMessage, len,
            p_dst + SAMPLE_AESGCM_MAC_SIZE + SAMPLE_AESGCM_IV_SIZE,
            iv,
            SAMPLE_AESGCM_IV_SIZE,
            NULL, 0,
            (sample_aes_gcm_128bit_tag_t *) (p_dst));
/*
    if(ret == SAMPLE_SUCCESS) printf("ENCRYPT RESULT: SAMPLE_SUCCESS");
    if(ret == SAMPLE_ERROR_INVALID_PARAMETER) printf("ENCRYPT RESULT: SAMPLE_ERROR_INVALID_PARAMETER");
    if(ret == SAMPLE_ERROR_OUT_OF_MEMORY) printf("ENCRYPT RESULT: SAMPLE_ERROR_OUT_OF_MEMORY");
    if(ret == SAMPLE_ERROR_UNEXPECTED) printf("ENCRYPT RESULT: SAMPLE_ERROR_UNEXPECTED");
*/
    memcpy(encMessageOut,p_dst,lenOut);
}

void utility_decrypt_file(unsigned char *encMessageIn, size_t len, unsigned char *decMessageOut, size_t lenOut, const sample_aes_gcm_128bit_key_t (*key)[16])
{
    uint8_t *encMessage = (uint8_t *) encMessageIn;
    uint8_t p_dst[lenOut];
    sample_status_t ret;

    printf("INIT CLIENT DECRYPTION...");

    ret = sample_rijndael128GCM_encrypt(
             *key,
            encMessage,
            lenOut,
            p_dst,
            encMessage + SAMPLE_AESGCM_MAC_SIZE, SAMPLE_AESGCM_IV_SIZE,
            NULL, 0,
            (sample_aes_gcm_128bit_tag_t *) encMessage);


//    ret = sample_rijndael128GCM_encrypt(
//            *key,
//            encMessage +SAMPLE_AESGCM_MAC_SIZE + SAMPLE_AESGCM_IV_SIZE,
//            lenOut,
//            p_dst,
//            encMessage + SAMPLE_AESGCM_MAC_SIZE, SAMPLE_AESGCM_IV_SIZE,
//            NULL, 0,
//            (sample_aes_gcm_128bit_tag_t *) encMessage);
/*
    if(ret == SAMPLE_SUCCESS) printf("DECRYPT RESULT: SAMPLE_SUCCESS");
    if(ret == SAMPLE_ERROR_INVALID_PARAMETER) printf("DECRYPT RESULT: SAMPLE_ERROR_INVALID_PARAMETER");
    if(ret == SAMPLE_ERROR_OUT_OF_MEMORY) printf("DECRYPT RESULT: SAMPLE_ERROR_OUT_OF_MEMORY");
    if(ret == SAMPLE_ERROR_UNEXPECTED) printf("DECRYPT RESULT: SAMPLE_ERROR_UNEXPECTED");
*/
    memcpy(decMessageOut, p_dst, lenOut);
}