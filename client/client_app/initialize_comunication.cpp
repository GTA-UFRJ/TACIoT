/*
 * Grupo de Teleinformatica e Automacao (GTA, Coppe, UFRJ)
 * Autor: Guilherme Araujo Thomaz
 * Data da ultima modificacao: 30/11/2021
 * Descricao: espera mensgaens do servdior para se atestar. 
 */

#include "request_register.h"
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <iostream>
#include <string.h>
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

    using namespace httplib;
    Server svr;
    svr.Get(R"(/attest/type=([0-9a-f]+)&size=([0-9a-f]+)&align=([0-9a-f]+)&body=([0-9a-f]+))", 
            [&](const Request& req, Response& res) {
        
        std::string a_type = req.matches[1].str();
        sprintf(c_type,"%x",a_type);
        type = (uint8_t)strtoul(c_type, NULL, 16);

        std::string a_size = req.matches[2].str();
        sprintf(c_size,"%x",a_size);
        size = (uint32_t)strtoul(c_size, NULL, 16);

        std::string a_align = req.matches[3].str();
        sprintf(c_align,"%x",a_size);
        char auxiliar[3];
        auxiliar[2] = '\0';
        for (int i=0; i<7-1; i=i+2)
        {
            auxiliar[0] = c_align[i];
            auxiliar[1] = c_align[i+1];
            align[i/2] = (uint8_t)strtoul(auxiliar, NULL, 16);
        }

        c_body = (char*)malloc((size*2+1)*sizeof(char));
        body = (uint8_t*)malloc(size*sizeof(uint8_t));
        std::string a_body = req.matches[4].str();
        sprintf(c_body,"%x",a_body);
        for (int i=0; i<(size*2)-1; i=i+2)
        {
            auxiliar[0] = c_body[i];
            auxiliar[1] = c_body[i+1];
            body[i/2] = (uint8_t)strtoul(auxiliar, NULL, 16);
        }
        free(c_body);

        p_req->type = type;
        p_req->size = size;
        memcpy(&p_req->align[0],align,3*sizeof(uint8_t));
        memcpy(&p_req->body[0],body,size*sizeof(uint8_t));
        free(body);

        int ret = 0;
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

        if(0 == ret)
        {
            res_body = (char*)malloc((1+p_resp_msg->size)*2*sizeof(char));         
            for (int i=0;i<p_resp_msg->size;i++)
            {
                sprintf(auxiliar,"%02x",p_resp_msg->body[i]);
                res_body[2*i] = auxiliar[0];
                res_body[2*i+1] = auxiliar[1];
            }
            response = (char*)malloc(((sizeof(p_resp_msg->type)+
                                     sizeof(p_resp_msg->align) +
                                     sizeof(p_resp_msg->size)  +
                                     sizeof(p_resp_msg->status)+
                                     p_resp_msg->size*sizeof(uint8_t))*2+5)*
                                     sizeof(char)); 
            sprintf (response, "%02x:%02x%02x:%02x:%02x:%s",
                     p_resp_msg->type,
                     p_resp_msg->status[0],
                     p_resp_msg->status[1],
                     p_resp_msg->size,
                     p_resp_msg->align[0],
                     res_body);
            body[2*p_resp_msg->size] = '\0';
            free(body);
            res.set_content(response,"text/plain");
            free(response);
        }
    });
    svr.listen(TEST_CLIENT_URL,COMUNICATION_PORT);
}
