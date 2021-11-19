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

#ifndef _UTILS_H_
#define _UTILS_H_

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#ifndef _ERRNO_T_DEFINED
#define _ERRNO_T_DEFINED
typedef int errno_t;
#endif

#ifndef SAFE_FREE
#define SAFE_FREE(ptr) {if (NULL != (ptr)) {free(ptr); (ptr) = NULL;}}
#endif

errno_t memcpy_s(void *dest, size_t numberOfElements, const void *src,
                 size_t count);

void PRINT_BYTE_ARRAY(FILE *file, void *mem, uint32_t len);

typedef enum {
    OK,                         //0
    GET_EGID_FAIL,              //1
    MSG0_MEM_ALLOC_FAIL,        //2
    MSG0_SEND_FAIL,             //3
    SELCT_ATT_KEY_ID_FAIL,      //4 
    CREATE_ENCLAVE_FAIL,        //5 
    ENCLAVE_INIT_ATT_FAIL,      //6 
    MSG1_MEM_ALLOC_FAIL,        //7 
    MSG1_RETRIEVE_FAIL,         //8 
    MSG1_SEND_FAIL,             //9
    MSG2_RECV_FAIL,             //10
    MSG2_PROC_FAIL,             //11
    MSG3_MEM_ALLOC_FAIL,        //12
    MEMCPY_FAIL,                //13
    MSG3_SEND_FAIL,             //14
    INVALID_MSG4,               //15
    INTEGRITY_FAIL,             //16
    ATT_RESULT_MSG_FAIL,        //17
    SK_SECRET_FAILED,           //18
    CLOSE_ENCLAVE_FAIL,         //19
    UNKNOWN                     //x
} error_code;

#endif // _UTILS_H_
