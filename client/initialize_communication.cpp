/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Description: wait for server messages to attest
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
#include "initialize_communication.h"
#include HTTPLIB_PATH

int initialize_communication()
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

    // Client offers attestation service for cloud
    Server svr;
    svr.Get("/stop", [&](const Request& req, Response& res) {
        svr.stop();
    });
    svr.Get(R"(/attest/type=([0-9a-f]+)&size=([0-9a-f]+)&align=([0-9a-f]+)&body=([0-9a-f]+))", 
            [&](const Request& req, Response& res) {
        
        std::this_thread::sleep_for(std::chrono::milliseconds(LATENCY_MS)); 

        fprintf(stdout,"\nClient received mensage\n");
        
        // Converte messages in strings and numbers
        std::string a_type = req.matches[1].str();
        strcpy(c_type, a_type.c_str());
        type = (uint8_t)strtoul(c_type, NULL, 16);

        std::string a_size = req.matches[2].str();
        strcpy(c_size, a_size.c_str());
        size = (uint32_t)strtoul(c_size, NULL, 16);

        std::string a_align = req.matches[3].str();
        strcpy(c_align, a_align.c_str());
        char auxiliar[3];
        auxiliar[2] = '\0';
        for (int i=0; i<6-1; i=i+2)
        {
            auxiliar[0] = c_align[i];
            auxiliar[1] = c_align[i+1];
        }
        
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
        
        // Fill attestation request strtucture with received fields
        p_req = (ra_samp_request_header_t*)malloc(sizeof(uint8_t)*(1+4+3+size));
        p_req->type = type;
        p_req->size = size;
        memcpy(&p_req->align[0],align,3*sizeof(uint8_t));
        memcpy(&p_req->body[0],body,size*sizeof(uint8_t));
        free(body);

        // Process messages and generate response 
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

        // Send response message
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
            fprintf(stdout,"\nClient sent %s\n",response);
            res.set_content(response,"text/plain");
            free(response);
        }
    });

    // Client serves cloud in 7777 port for attestation
    fprintf(stdout,"\nClient started attestation service\n");
    //fprintf(stdout,"Latency: %d\n", LATENCY_MS);
    svr.listen(TEST_CLIENT_URL,COMUNICATION_PORT);
    return ret;
}
