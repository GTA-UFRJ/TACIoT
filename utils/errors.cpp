/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Descripton: error type definition
 */

#include "errors.h"
#include <stdio.h>

FILE* out_stream = stderr;

server_error_t print_error_message(server_error_t error) {

    if(!error) return error;
    fprintf(out_stream, "Error %d: ", (int)error);
    switch (error) {

        case INIT_ERROR:
        fprintf(out_stream, "Insuficient arguments\n");
        break;

        case ENCALVE_INIT_ERROR:
        fprintf(out_stream, "Failed to initialize enclave\n");
        break;

        case INVALID_HTTP_MESSAGE_SIZE_FIELD_ERROR:
        fprintf(out_stream, "Failed to detect HTTP message size\n");
        break;

        case HTTP_MESSAGE_SIZE_OVERFLOW_ERROR:
        fprintf(out_stream, "HTTP message bigger than the maximum size\n");
        break;

        case INVALID_ENCRYPTED_SIZE_FIELD_ERROR:
        fprintf(out_stream, "Invalid encrypted size message format\n");
        break;

        case INVALID_ENCRYPTED_FIELD_ERROR:
        fprintf(out_stream, "Invalid encrypted publication message format\n");
        break;

        case OPEN_DATABASE_ERROR:
        fprintf(out_stream, "Can't open database\n");
        break;

        case OPEN_CLIENT_KEY_FILE_ERROR:
        fprintf(out_stream, "Failed to open the client file\n");
        break;

        case OPEN_SERVER_KEY_FILE_ERROR:
        fprintf(out_stream, "Failed to open the server file\n");
        break;

        case MESSAGE_DECRYPTION_ERROR:
        fprintf(out_stream, "Error decrypting publisher message\n");
        break;

        case AUTHENTICATION_ERROR:
        fprintf(out_stream, "Invalid encrypted pk. Could not authenticate client\n");
        break;

        case DATA_ENCRYPTION_ERROR:
        fprintf(out_stream, "Error encrypting data for storing\n");
        break;

        case ENCRYPTED_OVERFLOW_ERROR:
        fprintf(out_stream, "Insuficient memory for encrypted result\n");
        break;

        case NO_PROCESSING_ENCLAVE_ERROR:
        fprintf(out_stream, "Enclave problem inside no_processing_s()\n");
        break;

        case DB_INSERT_EXECUTION_ERROR:
        fprintf(out_stream, "Failed to publish message\n");
        break;

        case DATA_DECRYPTION_ERROR:
        fprintf(out_stream, "Error decrypting stored data\n");
        break;

        case INVALID_PAYLOAD_ERROR:
        fprintf(out_stream, "Invalid payload format\n");
        break;

        case GET_DB_STATEMENT_ENCLAVE_ERROR:
        fprintf(out_stream, "Enclave problem inside get_db_request_s()\n");
        break;

        case INVALID_DB_STATEMENT_ERROR:
        fprintf(out_stream, "Invalid database statement\n");
        break;

        case SUM_ENCRYPTED_ENCLAVE_ERROR:
        fprintf(out_stream, "Enclave problem inside sum_encrypted_data_s()\n");
        break;

        case DB_SELECT_EXECUTION_ERROR:
        fprintf(out_stream, "Failed to query message\n");
        break;

        case HTTP_SEND_ERROR:
        fprintf(out_stream, "Error sending HTTP message to server\n");
        break;

        case HTTP_RESPONSE_ERROR:
        fprintf(out_stream, "Server responded with an HTTP error\n");
        break;

        case CLIENT_ENCRYPTION_ERROR:
        fprintf(out_stream, "Error encrypting message for sending\n");
        break;

        case CLIENT_DECRYPTION_ERROR:
        fprintf(out_stream, "Error decrypting returned message\n");
        break;

        case INVALID_HTTP_RESPONSE_SIZE_FIELD_ERROR:
        fprintf(out_stream, "Failed to detect HTTP response size\n");
        break;

        case HTTP_RESPONSE_SIZE_OVERFLOW_ERROR:
        fprintf(out_stream, "HTTP response bigger than the maximum size\n");
        break;

        case INVALID_ENCRYPTED_RESPONSE_ERROR:
        fprintf(out_stream, "Invalid encrypted response format\n");
        break;

        case OUT_OF_BOUND_INDEX:
        fprintf(out_stream, "Index out of bound\n");
        break;

        case ACCESS_DENIED:
        fprintf(out_stream, "Access denied\n");
        break;

        case RETRIEVE_DATA_ENCLAVE_ERROR:
        fprintf(out_stream, "Enclave problem inside retrieve_data()\n");
        break;

        case INVALID_ERROR_CODE_FORMAT_ERROR:
        fprintf(out_stream, "Invalid error code formatation received from server\n");
        break;

        case ALREDY_REGISTERED_ERROR:
        fprintf(out_stream, "Alredy registered client ID\n");
        break;

        case KEY_REGISTRATION_ERROR:
        fprintf(out_stream, "Could not save client key\n");
        break;

        default:
        fprintf(out_stream, "Unknown error\n");
        break;
    }

    return error;
}
