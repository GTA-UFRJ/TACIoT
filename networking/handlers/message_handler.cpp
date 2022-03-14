/*
 * Grupo de Teleinformatica e Automacao (GTA, Coppe, UFRJ)
 * Autor: Guilherme Araujo Thomaz
 * Data da ultima modificacao: 17/12/2021
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
#include <chrono>
#include <thread>
#include "message_handler.h"
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
    ra_samp_response_header_t resp_msg;
    char response_msg[176+9+1];

    if((NULL == client_url) ||
        (NULL == p_req) ||
        (NULL == p_resp))
    {
        return -1;
    }

    // Inicializa um cliente HTTP para se atestar para o cliente
    char url[URL_MAX_SIZE];
    sprintf(url,"%s",client_url);
    char* ip = strtok((char*)url,":");
    char* port = strtok(NULL,":");
    fprintf(stdout,"%s e %s\n",ip,port);
    int cli_port = (int)strtol(port,NULL,10);
    const std::string cli_ip(ip);
    httplib::Client cli(cli_ip,cli_port);
    //httplib::Error cli_err;

    // Gera mensagem de atestacao para enviar para o cleinte
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

    // Tenta se comunicar com o cliente x vezes
    int tries = 0;
    int i;
    char* type;
    char* status;
    char status0[3];
    char status1[3];
    char* size;
    char* align;
    char* res_body;
    unsigned int u_type;
    unsigned int u_status0;
    unsigned int u_status1;
    unsigned int u_size;
    unsigned int u_align;
    char auxiliar[3];
    bool sent = false;
    while (sent == false)
    {
        // Evnia mensagem e obtem resposta do cliente
        if (auto res = cli.Get(http_code)){
            fprintf(stdout,"\nServidor enviou: %s\n",http_code);
            sent = true;
            if (res->status == 200) {
                // fprintf(stdout, "Response: %s\n", res->body);
                fprintf(stdout,"\nServidor recebeu: \n");
                std::this_thread::sleep_for(std::chrono::milliseconds(LATENCY_MS));

                // Obtem os campos da resposta na forma de string
                //std::cout << res->body << std::endl;
                fprintf(stdout,"\n%s\n",res->body.c_str());
                sprintf(response_msg,"%s",res->body.c_str());
                type = strtok((char*)response_msg,":");
                status = strtok(NULL,":");
                status0[0] = status[0];
                status0[1] = status[1];
                status0[2] = '\0';
                status1[0] = status[2];
                status1[1] = status[3];
                status1[2] = '\0';
                size = strtok(NULL,":");
                align = strtok(NULL,":");
                res_body = strtok(NULL,":");

                // Transforma os caracteres em hexadecimal
                u_type = (unsigned)strtoul(type,NULL,16);
                resp_msg.type = uint8_t(u_type);
                u_status0 = (unsigned)strtoul(status0,NULL,16);
                u_status1 = (unsigned)strtoul(status1,NULL,16);
                resp_msg.status[0] = uint8_t(u_status0);
                resp_msg.status[1] = uint8_t(u_status1);
                u_size = (unsigned)strtoul(size,NULL,16);
                resp_msg.size = uint32_t(u_size);
                u_align = (unsigned)strtoul(align,NULL,16);
                resp_msg.align[0] = uint8_t(u_align);

                // Preenche a estrutura da resposta
                auxiliar[2] = '\0';
                i = 0;
                ra_free_network_response_buffer(p_resp_msg);
                p_resp_msg = (ra_samp_response_header_t*)malloc(sizeof(uint8_t)*(1+2+4+u_size));       
                p_resp_msg->type = resp_msg.type;
                p_resp_msg->status[0] = resp_msg.status[0];
                p_resp_msg->status[1] = resp_msg.status[1];
                p_resp_msg->size = resp_msg.size;
                p_resp_msg->align[1] = resp_msg.align[1];
                for (i=0; i<(u_size*2)-1; i=i+2)
                {
                    auxiliar[0] = res_body[i];
                    auxiliar[1] = res_body[i+1];
                    p_resp_msg->body[i/2] = (uint8_t)strtoul(auxiliar,NULL,16);
                    //fprintf(stdout,"%02x ",p_resp_msg->body[i/2]);
                }

            } 
        } else {
            // Espera 400ms antes de tentar denovo
            fprintf(stdout, "HTTP Error: %d\n", (int)res.error());
            using namespace std::this_thread; // sleep_for, sleep_until
            using namespace std::chrono; // nanoseconds, system_clock, seconds

            sleep_for(nanoseconds(10));
            sleep_until(system_clock::now() + milliseconds(2500));
        }
        if (tries < 20)
        {
            tries++;
        } else {
            sent = false;
        }
    }
    free(http_code);

    // Retorna resposta do cliente para a funcao de atestacao que chamou essa
    *p_resp = p_resp_msg;
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