/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Descripton: exchange messages with client for attestation
 * 
 * This code was modified following access permissions defined
 * by Intel Corporation license, presented as follows
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

#ifndef _REGISTER_CLIENT_H_
#define _REGISTER_CLIENT_H_

#include <stdlib.h>
#include <stdint.h>
#include "utils.h"
#include "sgx_tcrypto.h"

#ifdef  __cplusplus
extern "C" {
#endif

#define MSG1_BODY_SIZE              68
#define MSG2_BODY_SIZE              176
#define MSG3_BODY_SIZE              1452
#define ATTESTATION_MSG_BODY_SIZE   145

error_code attest_client(char* client_url, sgx_ec256_public_t* client_pk);

#ifdef  __cplusplus
}
#endif

#endif // _REGISTER_CLIENT_H_
