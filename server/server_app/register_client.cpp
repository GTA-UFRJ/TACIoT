/*
 * Grupo de Teleinformatica e Automacao (GTA, Coppe, UFRJ)
 * Autor: Guilherme Araujo Thomaz
 * Data da ultima modificacao: 15/11/2021
 * Descrição: troca mensagens com o cliente para atestacao
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

#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <string.h>

#include "register_client.h"
#include "message_handler.h"
#include "utils.h"
#include "utils_sgx.h"
#include "register_client.h"
#include "config_macros.h"
#include "server_enclave_u.h"
#include "remote_attestation_result.h"

#include "sgx_eid.h"
#include "sgx_ukey_exchange.h"
#include "sgx_urts.h"
#include "sgx_uae_epid.h"
#include "sgx_uae_quote_ex.h"
#include "sgx_tcrypto.h"

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

void PRINT_ATTESTATION_SERVICE_RESPONSE(
    FILE *file,
    ra_samp_response_header_t *response)
{
    if(!response)
    {
        fprintf(file, "\t\n( null )\n");
        return;
    }

    fprintf(file, "RESPONSE TYPE:   0x%x\n", response->type);
    fprintf(file, "RESPONSE STATUS: 0x%x 0x%x\n", response->status[0],
            response->status[1]);
    fprintf(file, "RESPONSE BODY SIZE: %u\n", response->size);

    if(response->type == TYPE_RA_MSG2)
    {
        sgx_ra_msg2_t* p_msg2_body = (sgx_ra_msg2_t*)(response->body);

        fprintf(file, "MSG2 gb - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->g_b), sizeof(p_msg2_body->g_b));

        fprintf(file, "MSG2 spid - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->spid), sizeof(p_msg2_body->spid));

        fprintf(file, "MSG2 quote_type : %hx\n", p_msg2_body->quote_type);

        fprintf(file, "MSG2 kdf_id : %hx\n", p_msg2_body->kdf_id);

        fprintf(file, "MSG2 sign_gb_ga - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->sign_gb_ga),
                         sizeof(p_msg2_body->sign_gb_ga));

        fprintf(file, "MSG2 mac - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->mac), sizeof(p_msg2_body->mac));

        fprintf(file, "MSG2 sig_rl - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->sig_rl),
                         p_msg2_body->sig_rl_size);
    }
    else if(response->type == TYPE_RA_ATT_RESULT)
    {
        sample_ra_att_result_msg_t *p_att_result =
            (sample_ra_att_result_msg_t *)(response->body);
        fprintf(file, "ATTESTATION RESULT MSG platform_info_blob - ");
        PRINT_BYTE_ARRAY(file, &(p_att_result->platform_info_blob),
                         sizeof(p_att_result->platform_info_blob));

        fprintf(file, "ATTESTATION RESULT MSG mac - ");
        PRINT_BYTE_ARRAY(file, &(p_att_result->mac), sizeof(p_att_result->mac));

        fprintf(file, "ATTESTATION RESULT MSG secret.payload_tag - %u bytes\n",
                p_att_result->secret.payload_size);

        fprintf(file, "ATTESTATION RESULT MSG secret.payload - ");
        PRINT_BYTE_ARRAY(file, p_att_result->secret.payload,
                p_att_result->secret.payload_size);
    }
    else
    {
        fprintf(file, "\nERROR in printing out the response. "
                       "Response of type not supported %d\n", response->type);
    }
}

#define _T(x) x
error_code attest_client(char* client_url, sgx_ec256_public_t* client_pk)
{
    int ret = 0;
    error_code error = OK;
    ra_samp_request_header_t *p_msg0_full = NULL;
    ra_samp_response_header_t *p_msg0_resp_full = NULL;
    ra_samp_request_header_t *p_msg1_full = NULL;
    ra_samp_response_header_t *p_msg2_full = NULL;
    sgx_ra_msg3_t *p_msg3 = NULL;
    ra_samp_response_header_t* p_att_result_msg_full = NULL;
    sgx_enclave_id_t enclave_id = 0;
    int enclave_lost_retry_time = 1;
    int busy_retry_time = 4;
    sgx_ra_context_t context = INT_MAX;
    sgx_status_t status = SGX_SUCCESS;
    ra_samp_request_header_t* p_msg3_full = NULL;
    sgx_att_key_id_t selected_key_id = {0}; // Nao encontrei onde esta a definicao
    //FILE* OUTPUT = fopen("/dev/null","a");
    FILE* OUTPUT = stdout;
    sgx_ra_msg2_t* p_msg2_body;
    uint32_t msg3_size; 
    sample_ra_att_result_msg_t * p_att_result_msg_body;
    bool attestation_passed;
    uint32_t* extended_epid_group_id_memory_address;

    // Obtem ID de grupo EPID
    uint32_t extended_epid_group_id = 0;
    ret = sgx_get_extended_epid_group_id(&extended_epid_group_id);
    if (SGX_SUCCESS != ret)
    {
        fprintf(OUTPUT, "\nError, call sgx_get_extended_epid_group_id fail [%s].",
                __FUNCTION__);
        return GET_EGID_FAIL;
    }
    fprintf(OUTPUT, "\nCall sgx_get_extended_epid_group_id success.");

    // Gera mensagem 0 (quatro bytes de zero)
    p_msg0_full = (ra_samp_request_header_t*) malloc(sizeof(ra_samp_request_header_t)
          +sizeof(uint32_t));
    if (NULL == p_msg0_full)
    {
        error = MSG0_MEM_ALLOC_FAIL;
        goto CLEANUP;
    }
    p_msg0_full->type = TYPE_RA_MSG0;
    p_msg0_full->size = sizeof(uint32_t);

    extended_epid_group_id_memory_address = (uint32_t*)((uint8_t*)p_msg0_full + sizeof(ra_samp_request_header_t));
    *extended_epid_group_id_memory_address = extended_epid_group_id;
    fprintf(OUTPUT, "\nMSG0 body generated -\n");
    PRINT_BYTE_ARRAY(OUTPUT, p_msg0_full->body, p_msg0_full->size);
    // Manda mensagem 0 para o client (o formato foi combinado previamente)
    fprintf(OUTPUT, "\nSending msg0 to client.\n");
    ret = ra_network_send_receive(client_url,
                p_msg0_full,
                &p_msg0_resp_full);
    if (ret != 0)
    {
        error = MSG0_SEND_FAIL;
        fprintf(OUTPUT, "\nError, ra_network_send_receive for msg0 failed "
           "[%s].", __FUNCTION__);
        goto CLEANUP;
    }
    fprintf(OUTPUT, "\nSent MSG0 to client.\n");

    ret = sgx_select_att_key_id(p_msg0_resp_full->body, p_msg0_resp_full->size, &selected_key_id);
    if(SGX_SUCCESS != ret)
    {
        error = SELCT_ATT_KEY_ID_FAIL;
        fprintf(OUTPUT, "\nInfo, call sgx_select_att_key_id fail, current platform configuration doesn't support this attestation key ID. [%s]",
                __FUNCTION__);
        goto CLEANUP;
    }
    fprintf(OUTPUT, "\nCall sgx_select_att_key_id success.");
        
    do
    {
        // Arquivo do token do enclave correspondente ao cliente
        char token_path[PATH_MAX_SIZE];
        char enclave_path[PATH_MAX_SIZE];
        char token_sufix[16+1];
        sprintf(token_sufix, "%x%x%x%x",(client_pk->gx)[0],(client_pk->gy)[0],(client_pk->gx)[1],(client_pk->gy)[1]);
        ret = sprintf(token_path, "%s/%s", TOKENS_PATH, token_sufix);
        ret = sprintf(enclave_path,"%s",ENCLAVE_PATH);

        // Inicializa o enclave (ECALL)
        ret = initialize_enclave(&enclave_id, token_path, enclave_path);
        if(SGX_SUCCESS != ret)
        {
            error = CREATE_ENCLAVE_FAIL; 
            fprintf(OUTPUT, "\nError, call sgx_create_enclave fail [%s].",
                    __FUNCTION__);
            goto CLEANUP;
        }
        fprintf(OUTPUT, "\nCall sgx_create_enclave success.");

        // Inicia a atestacao obtendo os parametos para o DH (ECALL)
        ret = enclave_init_ra(enclave_id,
                              &status,
                              false,
                              &context,
                              client_pk);
    } while (SGX_ERROR_ENCLAVE_LOST == ret && enclave_lost_retry_time--);
    
   if(SGX_SUCCESS != ret || status)
    {
        error = ENCLAVE_INIT_ATT_FAIL;
        fprintf(OUTPUT, "\nError, call enclave_init_ra fail [%s].",
                __FUNCTION__);
        goto CLEANUP;
    }
    fprintf(OUTPUT, "\nCall enclave_init_ra success.");
 
    // Prepara mensagem 1 contendo Ga para o DH
    p_msg1_full = (ra_samp_request_header_t*)
                   malloc(sizeof(ra_samp_request_header_t)
                        + sizeof(sgx_ra_msg1_t));
    if(NULL == p_msg1_full)
    {
        error = MSG1_MEM_ALLOC_FAIL;
        goto CLEANUP;
    }
    p_msg1_full->type = TYPE_RA_MSG1;
    p_msg1_full->size = sizeof(sgx_ra_msg1_t);
   do
    {
        // Obtem Ga do enclave
        ret = sgx_ra_get_msg1_ex(&selected_key_id, context, enclave_id, sgx_ra_get_ga,
                             (sgx_ra_msg1_t*)((uint8_t*)p_msg1_full
                             + sizeof(ra_samp_request_header_t)));
        sleep(1);
    } while (SGX_ERROR_BUSY == ret && busy_retry_time--);
    if(SGX_SUCCESS != ret)
    {
        error = MSG1_RETRIEVE_FAIL;
        fprintf(OUTPUT, "\nError, call sgx_ra_get_msg1_ex fail [%s].",
                __FUNCTION__);
        goto CLEANUP;
    }
    else
    {
       fprintf(OUTPUT, "\nCall sgx_ra_get_msg1_ex success.\n");
       fprintf(OUTPUT, "\nMSG1 body generated -\n");
       PRINT_BYTE_ARRAY(OUTPUT, p_msg1_full->body, p_msg1_full->size);
    } 
    
   // Envia mensagem 1 recebe mensagem 2
    fprintf(OUTPUT, "\nSending msg1 to remote attestation service provider."
                    "Expecting msg2 back.\n");
    ret = ra_network_send_receive(client_url,
                                 p_msg1_full,
                                 &p_msg2_full);

    if(ret != 0 || !p_msg2_full)
    {
        error = MSG1_SEND_FAIL;
        fprintf(OUTPUT, "\nError, ra_network_send_receive for msg1 failed "
                        "[%s].", __FUNCTION__);
        goto CLEANUP;
    }
    else
    {
        // Checa mensagem 2 contendo Gb, assinatura de GaGb e assinatura
        if(TYPE_RA_MSG2 != p_msg2_full->type)
        {
            error = MSG2_RECV_FAIL;
            fprintf(OUTPUT, "\nError, didn't get MSG2 in response to MSG1. "
                            "[%s].", __FUNCTION__);

            goto CLEANUP;
        }
        fprintf(OUTPUT, "\nSent MSG1 to remote attestation service "
                        "provider. Received the following MSG2:\n");
        PRINT_BYTE_ARRAY(OUTPUT, p_msg2_full,
                         (uint32_t)sizeof(ra_samp_response_header_t)
                         + p_msg2_full->size);
        fprintf(OUTPUT, "\nA more descriptive representation of MSG2:\n");
        PRINT_ATTESTATION_SERVICE_RESPONSE(OUTPUT, p_msg2_full);
    }
    p_msg2_body = (sgx_ra_msg2_t*)((uint8_t*)p_msg2_full
                                 + sizeof(ra_samp_response_header_t));

    // Gera mensagem 3 contendo o quote (ECALL)
    msg3_size = 0;
    busy_retry_time = 2;
    do
    {
        ret = sgx_ra_proc_msg2_ex(&selected_key_id,
                                   context,
                                   enclave_id,
                                   sgx_ra_proc_msg2_trusted,
                                   sgx_ra_get_msg3_trusted,
                                   p_msg2_body,
                                   p_msg2_full->size,
                                   &p_msg3,
                                   &msg3_size);
    } while (SGX_ERROR_BUSY == ret && busy_retry_time--);
    if(!p_msg3)
    {
        error = MSG2_PROC_FAIL;
        fprintf(OUTPUT, "\nError, call sgx_ra_proc_msg2_ex fail. "
                        "p_msg3 = 0x%p [%s].", p_msg3, __FUNCTION__);
        goto CLEANUP;
    }
    if(SGX_SUCCESS != (sgx_status_t)ret)
    {
        error = MSG2_PROC_FAIL;
        fprintf(OUTPUT, "\nError, call sgx_ra_proc_msg2_ex fail. "
                        "ret = 0x%08x [%s].", ret, __FUNCTION__);
        goto CLEANUP;
    }
    else
    {
        fprintf(OUTPUT, "\nCall sgx_ra_proc_msg2_ex success.\n");
        fprintf(OUTPUT, "\nMSG3 - \n");
    }
    PRINT_BYTE_ARRAY(OUTPUT, p_msg3, msg3_size);

    p_msg3_full = (ra_samp_request_header_t*)malloc(
                   sizeof(ra_samp_request_header_t) + msg3_size);
    if(NULL == p_msg3_full)
    {
        error = MSG3_MEM_ALLOC_FAIL;
        goto CLEANUP;
    }
    p_msg3_full->type = TYPE_RA_MSG3;
    p_msg3_full->size = msg3_size;
    if(memcpy_s(p_msg3_full->body, msg3_size, p_msg3, msg3_size))
    {
        error = MEMCPY_FAIL;
        fprintf(OUTPUT,"\nError: INTERNAL ERROR - memcpy failed in [%s].",
                __FUNCTION__);
        goto CLEANUP;
    }

    // Eniva a mensagem 3 e recebe mensagem 4 com o resultado da atestação
    ret = ra_network_send_receive(client_url,
                                  p_msg3_full,
                                  &p_att_result_msg_full);
    if(ret || !p_att_result_msg_full)
    {
        error = MSG3_SEND_FAIL;
        fprintf(OUTPUT, "\nError, sending msg3 failed [%s].", __FUNCTION__);
        goto CLEANUP;
    }
    p_att_result_msg_body =
        (sample_ra_att_result_msg_t *)((uint8_t*)p_att_result_msg_full
                                       + sizeof(ra_samp_response_header_t));
    if(TYPE_RA_ATT_RESULT != p_att_result_msg_full->type)
    {
        error = INVALID_MSG4;
        fprintf(OUTPUT, "\nError. Sent MSG3 successfully, but the message "
                        "received was NOT of type att_msg_result. Type = "
                        "%d. [%s].", p_att_result_msg_full->type,
                         __FUNCTION__);
        goto CLEANUP;
    }
    else
    {
        fprintf(OUTPUT, "\nSent MSG3 successfully. Received an attestation "
                        "result message back\n.");
    }
    fprintf(OUTPUT, "\nATTESTATION RESULT RECEIVED - ");
    PRINT_BYTE_ARRAY(OUTPUT, p_att_result_msg_full->body,
                             p_att_result_msg_full->size);


    // Checa o MAC do reusltado com a chave MK (ECALL)
    ret = verify_att_result_mac(enclave_id,
            &status,
            context,
            (uint8_t*)&p_att_result_msg_body->platform_info_blob,
            sizeof(ias_platform_info_blob_t),
            (uint8_t*)&p_att_result_msg_body->mac,
            sizeof(sgx_mac_t));
    if((SGX_SUCCESS != ret) ||
      (SGX_SUCCESS != status))
    {
        ret = INTEGRITY_FAIL;
        fprintf(OUTPUT, "\nError: INTEGRITY FAILED - attestation result "
                        "message MK based cmac failed in [%s].",
                        __FUNCTION__);
        goto CLEANUP;
    }
    attestation_passed = true;

    // Checa o resultado da atestacao
    if(0 != p_att_result_msg_full->status[0]
       || 0 != p_att_result_msg_full->status[1])
    {
        error = ATT_RESULT_MSG_FAIL;
        fprintf(OUTPUT, "\nError, attestation result message MK based cmac "
                        "failed in [%s].", __FUNCTION__);
        attestation_passed = false;
    }

    // AQUI COMECA A COMUNICACAO DE DADOS
    // Pega o segredo enviado pelo cliente usando SK
    if(attestation_passed)
    {
        ret = put_secret_data(enclave_id,
                              &status,
                              context,
                              p_att_result_msg_body->secret.payload,
                              p_att_result_msg_body->secret.payload_size,
                              p_att_result_msg_body->secret.payload_tag);
        if((SGX_SUCCESS != ret)  || (SGX_SUCCESS != status))
        {
            error = SK_SECRET_FAILED;
            fprintf(OUTPUT, "\nError, attestation result message secret "
                            "using SK based AESGCM failed in [%s]. ret = "
                            "0x%0x. status = 0x%0x", __FUNCTION__, ret,
                             status);
            goto CLEANUP;
        }
    }
    fprintf(OUTPUT, "\nSecret successfully received from server.");
    fprintf(OUTPUT, "\nRemote attestation success!");
    error = OK;

    CLEANUP:
    if(INT_MAX != context)
    {
        ret = enclave_ra_close(enclave_id, &status, context);
        if(SGX_SUCCESS != ret || status)
        {
            error = CLOSE_ENCLAVE_FAIL;
            fprintf(OUTPUT, "\nError, call enclave_ra_close fail [%s].",
                    __FUNCTION__);
        }
        fprintf(OUTPUT, "\nCall enclave_ra_close success.");
    }
    sgx_destroy_enclave(enclave_id);
    ra_free_network_response_buffer(p_msg0_resp_full);
    p_msg0_resp_full = NULL;
    ra_free_network_response_buffer(p_msg2_full);
    p_msg2_full = NULL;
    ra_free_network_response_buffer(p_att_result_msg_full);
    p_att_result_msg_full = NULL;
    SAFE_FREE(p_msg3);
    SAFE_FREE(p_msg3_full);
    SAFE_FREE(p_msg1_full);
    SAFE_FREE(p_msg0_full);
    return error;
}
