/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Descripton: error type definition
 */

#ifndef _ERRORS_H_
#define _ERRORS_H_

typedef enum {
    OK,                                     // 0                 
    INIT_ERROR,                             // 1
    ENCALVE_INIT_ERROR,                     // 2
    INVALID_HTTP_MESSAGE_SIZE_FIELD_ERROR,  // 3
    HTTP_MESSAGE_SIZE_OVERFLOW_ERROR,       // 4
    INVALID_ENCRYPTED_SIZE_FIELD_ERROR,     // 5
    INVALID_ENCRYPTED_FIELD_ERROR,          // 6
    OPEN_DATABASE_ERROR,                    // 7
    OPEN_CLIENT_KEY_FILE_ERROR,             // 8
    OPEN_SERVER_KEY_FILE_ERROR,             // 9
    MESSAGE_DECRYPTION_ERROR,               // 10
    AUTHENTICATION_ERROR,                   // 11
    INVALID_DB_STATEMENT_ERROR,             // 12
    DB_SELECT_EXECUTION_ERROR,              // 13
    DATA_DECRYPTION_ERROR,                  // 14
    INVALID_PAYLOAD_ERROR,                  // 15
    DATA_ENCRYPTION_ERROR,                  // 16
    GET_DB_STATEMENT_ENCLAVE_ERROR,         // 17
    SUM_ENCRYPTED_ENCLAVE_ERROR,            // 18
    DB_INSERT_EXECUTION_ERROR,              // 19
    ENCRYPTED_OVERFLOW_ERROR,               // 20
    NO_PROCESSING_ENCLAVE_ERROR,            // 21
    INVALID_INDEX_FIELD_ERROR,              // 22
    INVALID_COMMAND_SIZE_FIELD_ERROR,       // 23
    OUT_OF_BOUND_INDEX,                     // 24
    MESSAGE_ENCRYPTION_ERROR,               // 25
    RETRIEVE_DATA_ENCLAVE_ERROR,            // 26
    ACCESS_DENIED,                          // 27
    DB_DELETE_EXECUTION_ERROR,              // 28
    OWNERSHIP_VIOLATION_ERROR,              // 29
    REVOKE_DATA_ENCLAVE_ERROR,              // 30
    INVALID_REGISTRATION_KEY_FIELD_ERROR,   // 31
    ALREDY_REGISTERED_ERROR,                // 32
    KEY_REGISTRATION_ERROR,                 // 33
    SEALING_DATA_ENCLAVE_ERROR,             // 34
    HTTP_SEND_ERROR,                        // 35
    HTTP_RESPONSE_ERROR,                    // 36
    CLIENT_ENCRYPTION_ERROR,                // 37
    CLIENT_DECRYPTION_ERROR,                // 38
    INVALID_HTTP_RESPONSE_SIZE_FIELD_ERROR, // 39
    HTTP_RESPONSE_SIZE_OVERFLOW_ERROR,      // 40
    INVALID_ENCRYPTED_RESPONSE_ERROR,       // 41
    INVALID_ERROR_CODE_FORMAT_ERROR         // 42
} server_error_t;

server_error_t print_error_message(server_error_t error);

#endif