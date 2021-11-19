/*
 * Grupo de Teleinformatica e Automacao (GTA, Coppe, UFRJ)
 * Autor: Guilherme Araujo Thomaz
 * Data da ultima modificacao: 17/11/2021
 * Descricao: funcoes auxiliares para enclaves 
 * 
 * Este codigo foi modificado partindo do repositorio de exemplos da SGX101
 *
 */

#ifndef SGX_UTILS_H_
#define SGX_UTILS_H_

#include <string>
#include <stdint.h>
#include "sgx_urts.h"

void print_error_message(sgx_status_t ret);

int initialize_enclave(sgx_enclave_id_t* eid, char* launch_token_path, char* enclave_name);

bool is_ecall_successful(sgx_status_t sgx_status, const std::string& err_msg, sgx_status_t ecall_return_value = SGX_SUCCESS);

#endif // SGX_UTILS_H_
