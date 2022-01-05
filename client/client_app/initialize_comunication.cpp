/*
 * Grupo de Teleinformatica e Automacao (GTA, Coppe, UFRJ)
 * Autor: Guilherme Araujo Thomaz
 * Data da ultima modificacao: 17/12/2021
 * Descricao: espera mensgaens do servdior para se atestar. 
 */

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <iostream>
#include <string.h>
#include <chrono>
#include <thread>
#include "request_register.h"
#include "config_macros.h"
#include HTTPLIB_PATH

int main(void)
{
    ra_samp_request_header_t* p_req;
    char c_type[3];
    uint8_t type;
    char c_size[4];
    uint32_t size;
    char c_align[7];
    uint8_t align[3]; 
    char* c_body;
    uint8_t* body;
    int ret = 0;
    using namespace httplib;
/*
     // Cliente HTTP se conecta com o servidor
    char server_url[URL_MAX_SIZE];
    sprintf(server_url,SERVER_URL);
    const std::string srv_url(server_url);
    Client cli(srv_url, COMUNICATION_PORT_2);
    Error err = Error::Success;

    // Cliente envia mensagem para se registar, com seu endereço, porta e chave de atestacao   
    char get_msg[URL_MAX_SIZE];
    sprintf(get_msg,"/register/url=%s&port=%u&pk=%s",TEST_CLIENT_URL,COMUNICATION_PORT,CLIENT_GXGYPK);
    printf("\nCliente enviou: %s\n",get_msg);
    if (auto res = cli.Get(get_msg)) {
      if (res->status == 200) {
        fprintf(stdout,"\nCliente recebeu\n");
        std::cout << res->body << std::endl;
      }
    } else {
      err = res.error();
      printf("%d\n", (int)res.error());
    }   
*/

    // Cliente oferece um servico de atestacao a nuvem
    Server svr;
    svr.Get("/stop", [&](const Request& req, Response& res) {
        svr.stop();
    });
    svr.Get(R"(/attest/type=([0-9a-f]+)&size=([0-9a-f]+)&align=([0-9a-f]+)&body=([0-9a-f]+))", 
            [&](const Request& req, Response& res) {
        
        std::this_thread::sleep_for(std::chrono::milliseconds(LATENCY_MS)); 

        fprintf(stdout,"\nCliente recebeu mensagem\n");
        
        // Converte respostas em string e depois em numeros em hexadecimal
        std::string a_type = req.matches[1].str();
        strcpy(c_type, a_type.c_str());
        type = (uint8_t)strtoul(c_type, NULL, 16);

        std::string a_size = req.matches[2].str();
        strcpy(c_size, a_size.c_str());
        size = (uint32_t)strtoul(c_size, NULL, 16);

        // O campo de align possui 3 caracteres. Ex: 7f 00 00
        std::string a_align = req.matches[3].str();
        strcpy(c_align, a_align.c_str());
        char auxiliar[3];
        auxiliar[2] = '\0';
        for (int i=0; i<6-1; i=i+2)
        {
            auxiliar[0] = c_align[i];
            auxiliar[1] = c_align[i+1];
        }
        //fprintf(stdout,"\ntype = %u, size = %u, align[0,1,2] = %u %u %u", type, size, align[0], align[1], align[2]);
        // O tamanho do corpo eh especificado no campo size
        // Cada byte eh representado como 2 caracteres hexadecimais
        c_body = (char*)malloc((size*2+1)*sizeof(char));
        body = (uint8_t*)malloc(size*sizeof(uint8_t));
        std::string a_body = req.matches[4].str();
        strcpy(c_body, a_body.c_str());
        for (uint32_t i=0; i<(size*2)-1; i=i+2)
        {
            auxiliar[0] = c_body[i];
            auxiliar[1] = c_body[i+1];
            body[i/2] = (uint8_t)strtoul(auxiliar, NULL, 16);
        }
        free(c_body);
        
        // Preenche a estrutura de attestation request com os campos recebidos
        p_req = (ra_samp_request_header_t*)malloc(sizeof(uint8_t)*(1+4+3+size));
        p_req->type = type;
        p_req->size = size;
        memcpy(&p_req->align[0],align,3*sizeof(uint8_t));
        memcpy(&p_req->body[0],body,size*sizeof(uint8_t));
        free(body);

        // Processa mensagem e gera resposta
        ra_samp_response_header_t* p_resp_msg;
        char *response;
        char *res_body;
        switch (type)
        {
        case TYPE_RA_MSG0:
            ret = sp_ra_proc_msg0_req((const sample_ra_msg0_t*)((size_t)p_req
                + sizeof(ra_samp_request_header_t)),
                p_req->size,
                &p_resp_msg);
            if (0 != ret)
            {
                fprintf(stderr, "\nError, call sp_ra_proc_msg0_req fail [%s].",
                    __FUNCTION__);
            }        
        break;
        case TYPE_RA_MSG1:
            ret = sp_ra_proc_msg1_req((const sample_ra_msg1_t*)((size_t)p_req
                + sizeof(ra_samp_request_header_t)),
                p_req->size,
                &p_resp_msg);
            if (0 != ret)
            {
                fprintf(stderr, "\nError, call sp_ra_proc_msg1_req fail [%s].",
                    __FUNCTION__);
            }    
        break;
        case TYPE_RA_MSG3:
            ret = sp_ra_proc_msg3_req((const sample_ra_msg3_t*)((size_t)p_req
                + sizeof(ra_samp_request_header_t)),
                p_req->size,
                &p_resp_msg);
            if (0 != ret)
            {
                fprintf(stderr, "\nError, call sp_ra_proc_msg3_req fail [%s].",
                    __FUNCTION__);
            }    
        break;  
        default:
            ret = -1;
            fprintf(stderr, "\nError, unknown ra message type. Type = %d [%s].",
                p_req->type, __FUNCTION__);
        break;
        }

        // Se nao houve erro, envia uma mensagem de resposta
        if(0 == ret)
        {
            res_body = (char*)malloc((1+p_resp_msg->size)*2*sizeof(char));         
            for (uint32_t i=0;i<p_resp_msg->size;i++)
            {
                sprintf(auxiliar,"%02x",p_resp_msg->body[i]);
                res_body[2*i] = auxiliar[0];
                res_body[2*i+1] = auxiliar[1];
            }
            res_body[2*p_resp_msg->size] ='\0';

            size_t res_size;
            res_size = ((sizeof(p_resp_msg->type) +
                        sizeof(p_resp_msg->align) +
                        sizeof(p_resp_msg->size)  +
                        sizeof(p_resp_msg->status)+
                        p_resp_msg->size*sizeof(uint8_t))*2+5)*
                        sizeof(char);
            response = (char*)malloc(res_size); 

            sprintf (response, "%02x:%02x%02x:%08x:%02x:%s",
                     p_resp_msg->type,
                     p_resp_msg->status[0],
                     p_resp_msg->status[1],
                     p_resp_msg->size,
                     p_resp_msg->align[0],
                     res_body);
            free(res_body);
            fprintf(stdout,"\nCliente enviou: %s\n",response);
            res.set_content(response,"text/plain");
            free(response);
        }
    });

    // O cliente serve a nuvem na porta 7777 para atestacao
    fprintf(stdout,"\nCliente iniciou o servico de atestacao\n");
    fprintf(stdout,"Latencia: %d\n", LATENCY_MS);
    svr.listen(TEST_CLIENT_URL,COMUNICATION_PORT);
    return ret;
}
