/*
 * Grupo de Teleinformatica e Automacao (GTA, Coppe, UFRJ)
 * Autor: Guilherme Araujo Thomaz
 * Data da ultima modificacao: 30/11/2021
 * Descricao: interface de alto nivel para funcionalidades de envio
 * e recepcao de mensagens entre cliente e servidor.
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

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <iostream>
#include "message_handler.h"
#include "request_register.h"
#include "config_macros.h"
#include HTTPLIB_PATH

// Used to send requests to the service provider sample.  It
// simulates network communication between the ISV app and the
// ISV service provider.  This would be modified in a real
// product to use the proper IP communication.
//
// @param server_url String name of the server URL
// @param p_req Pointer to the message to be sent.
// @param p_resp Pointer to a pointer of the response message.

// @return int

int ra_network_send_receive(const char *client_url,
    const ra_samp_request_header_t *p_req,
    ra_samp_response_header_t **p_resp)
{
    int ret = 0;
    ra_samp_response_header_t* p_resp_msg;

    if((NULL == client_url) ||
        (NULL == p_req) ||
        (NULL == p_resp))
    {
        return -1;
    }

    httplib::Client cli(SERVER_URL, COMUNICATION_PORT);
    //httplib::Error cli_err;

    char* body;
    uint32_t byte_length;
    byte_length = p_req->size / sizeof(uint8_t); 
    body = (char*)malloc((1+(byte_length*2))*sizeof(char));
    char auxiliary_string[3];
    for (uint32_t i=0; i<byte_length; i++){
        sprintf(auxiliary_string,"%02x",p_req->body[i]);
        body[2*i] = auxiliary_string[0];
        body[2*i+1] = auxiliary_string[1];
    }
    body[2*byte_length] = '\0';

    char* http_code = (char*)malloc(URL_MAX_SIZE*sizeof(char));
    sprintf(http_code, "/attest/type=%02x&size=%02x&align=%02x%02x%02x&body=%s", 
                                                                p_req->type,
                                                                p_req->size, 
                                                                p_req->align[0],
                                                                p_req->align[1],
                                                                p_req->align[2],
                                                                body);
    free(body);
    fprintf(stdout,"%s\n",http_code);

    if (auto res = cli.Get(http_code)){
        if (res->status == 200) {
            // fprintf(stdout, "Response: %s\n", res->body);
            std::cout << res->body << std::endl;
        } 
    } else {
        fprintf(stdout, "HTTP Error: %d", (int)res.error());
    }
    free(http_code);

    // Modelo antigo
    switch(p_req->type)
    {
    case TYPE_RA_MSG0:
        
        ret = sp_ra_proc_msg0_req((const sample_ra_msg0_t*)((size_t)p_req
            + sizeof(ra_samp_request_header_t)),
            p_req->size,
            &p_resp_msg);
        if (0 != ret)
        {
            fprintf(stderr, "\nError, call sp_ra_proc_msg1_req fail [%s].",
                __FUNCTION__);
        }
        else
        {
            *p_resp = p_resp_msg;
        }
        break;

    case TYPE_RA_MSG1:

        ret = sp_ra_proc_msg1_req((const sample_ra_msg1_t*)((size_t)p_req
            + sizeof(ra_samp_request_header_t)),
            p_req->size,
            &p_resp_msg);
        if(0 != ret)
        {
            fprintf(stderr, "\nError, call sp_ra_proc_msg1_req fail [%s].",
                __FUNCTION__);
        }
        else
        {
            *p_resp = p_resp_msg;
        }
        break;

    case TYPE_RA_MSG3:

        ret =sp_ra_proc_msg3_req((const sample_ra_msg3_t*)((size_t)p_req +
            sizeof(ra_samp_request_header_t)),
            p_req->size,
            &p_resp_msg);
        if(0 != ret)
        {
            fprintf(stderr, "\nError, call sp_ra_proc_msg3_req fail [%s].",
                __FUNCTION__);
        }
        else
        {
            *p_resp = p_resp_msg;
        }
        break;

    default:
        ret = -1;
        fprintf(stderr, "\nError, unknown ra message type. Type = %d [%s].",
            p_req->type, __FUNCTION__);
        break;
    }

    return ret;
}

// Used to free the response messages.  In the sample code, the
// response messages are allocated by the SP code.
//
//
// @param resp Pointer to the response buffer to be freed.

void ra_free_network_response_buffer(ra_samp_response_header_t *resp)
{
    if(resp!=NULL)
    {
        free(resp);
    }
}