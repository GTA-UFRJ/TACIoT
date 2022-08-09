/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Descripton: serve client messages and register client
 */

#pragma once

#ifndef CLIENT_PK
#define CLIENT_PK
typedef struct sample_ec_pub_t
{
    uint8_t gx[32];
    uint8_t gy[32];
} sample_ec_pub_t;
#endif

// Gabarito de chave a ser recebida nos testes
static const sample_ec_pub_t g_sp_pub_key = {
    {
        0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf,
        0x85, 0xd0, 0x3a, 0x62, 0x37, 0x30, 0xae, 0xad,
        0x3e, 0x3d, 0xaa, 0xee, 0x9c, 0x60, 0x73, 0x1d,
        0xb0, 0x5b, 0xe8, 0x62, 0x1c, 0x4b, 0xeb, 0x38
    },
    {
        0xd4, 0x81, 0x40, 0xd9, 0x50, 0xe2, 0x57, 0x7b,
        0x26, 0xee, 0xb7, 0x41, 0xe7, 0xc6, 0x14, 0xe2,
        0x24, 0xb7, 0xbd, 0xc9, 0x03, 0xf2, 0x9a, 0x28,
        0xa8, 0x3c, 0xc8, 0x10, 0x11, 0x14, 0x5e, 0x06
    }
};

// Structure of the message sent by acess point (used by teh server)
typedef struct iot_message_t
{
    char pk[9];
    char type[7];
    uint32_t encrypted_size;
    uint8_t* encrypted;
} iot_message_t;

// Register shared key (not used, only for testes)
const sample_aes_gcm_128bit_key_t sha_key[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

// Structure of the message written to database
typedef struct stored_data_t
{
    char pk[9];
    char type[7];
    uint32_t encrypted_size;
    uint8_t* encrypted;
} stored_message_t;
