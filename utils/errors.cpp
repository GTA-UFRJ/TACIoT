/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Descripton: error type definition
 */

#include "errors.h"
#include <stdio.h>

FILE* out_stream = stderr;

std::string get_error_message(server_error_t error) {
    
    switch (error) {

        case INIT_ERROR:
        return std::string("Insuficient arguments");
        break;

        case ENCALVE_INIT_ERROR:
        return std::string("Failed to initialize enclave");
        break;

        case INVALID_HTTP_MESSAGE_SIZE_FIELD_ERROR:
        return std::string("Failed to detect HTTP message size");
        break;

        case HTTP_MESSAGE_SIZE_OVERFLOW_ERROR:
        return std::string("HTTP message bigger than the maximum size");
        break;

        case INVALID_ENCRYPTED_SIZE_FIELD_ERROR:
        return std::string("Invalid encrypted size message format");
        break;

        case INVALID_ENCRYPTED_FIELD_ERROR:
        return std::string("Invalid encrypted publication message format");
        break;

        case OPEN_DATABASE_ERROR:
        return std::string("Can't open database");
        break;

        case OPEN_CLIENT_KEY_FILE_ERROR:
        return std::string("Failed to open the client file");
        break;

        case OPEN_SERVER_KEY_FILE_ERROR:
        return std::string("Failed to open the server file");
        break;

        case MESSAGE_DECRYPTION_ERROR:
        return std::string("Error decrypting publisher message");
        break;

        case AUTHENTICATION_ERROR:
        return std::string("Invalid encrypted pk. Could not authenticate client");
        break;

        case DATA_ENCRYPTION_ERROR:
        return std::string("Error encrypting data for storing");
        break;

        case ENCRYPTED_OVERFLOW_ERROR:
        return std::string("Insuficient memory for encrypted result");
        break;

        case NO_PROCESSING_ENCLAVE_ERROR:
        return std::string("Enclave problem inside no_processing_s()");
        break;

        case DB_INSERT_EXECUTION_ERROR:
        return std::string("Failed to publish message");
        break;

        case DATA_DECRYPTION_ERROR:
        return std::string("Error decrypting stored data");
        break;

        case INVALID_PAYLOAD_ERROR:
        return std::string("Invalid payload format");
        break;

        case GET_DB_STATEMENT_ENCLAVE_ERROR:
        return std::string("Enclave problem inside get_db_request_s()");
        break;

        case INVALID_DB_STATEMENT_ERROR:
        return std::string("Invalid database statement");
        break;

        case SUM_ENCRYPTED_ENCLAVE_ERROR:
        return std::string("Enclave problem inside sum_encrypted_data_s()");
        break;

        case DB_SELECT_EXECUTION_ERROR:
        return std::string("Failed to query message");
        break;

        case HTTP_SEND_ERROR:
        return std::string("Error sending HTTP message to server");
        break;

        case HTTP_RESPONSE_ERROR:
        return std::string("Server responded with an HTTP error");
        break;

        case CLIENT_ENCRYPTION_ERROR:
        return std::string("Error encrypting message for sending");
        break;

        case CLIENT_DECRYPTION_ERROR:
        return std::string("Error decrypting returned message");
        break;

        case INVALID_HTTP_RESPONSE_SIZE_FIELD_ERROR:
        return std::string("Failed to detect HTTP response size");
        break;

        case HTTP_RESPONSE_SIZE_OVERFLOW_ERROR:
        return std::string("HTTP response bigger than the maximum size");
        break;

        case INVALID_ENCRYPTED_RESPONSE_ERROR:
        return std::string("Invalid encrypted response format");
        break;

        case OUT_OF_BOUND_INDEX:
        return std::string("Index out of bound");
        break;

        case ACCESS_DENIED:
        return std::string("Access denied");
        break;

        case RETRIEVE_DATA_ENCLAVE_ERROR:
        return std::string("Enclave problem inside retrieve_data()");
        break;

        case INVALID_ERROR_CODE_FORMAT_ERROR:
        return std::string("Invalid error code formatation received from server");
        break;

        case ALREDY_REGISTERED_ERROR:
        return std::string("Alredy registered client ID");
        break;

        case KEY_REGISTRATION_ERROR:
        return std::string("Could not save client key");
        break;

        default:
        return std::string("Unknown error");
        break;
    }
    return std::string("");
}

server_error_t print_error_message(server_error_t error) {
    if(!error) return error;
    fprintf(out_stream, "Error %d: ", (int)error);
    std::string error_message = get_error_message(error);
    fprintf(out_stream, "%s\n", error_message.c_str());
    return error;
}