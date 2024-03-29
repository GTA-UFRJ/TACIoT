/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Description: aggregate client data
 */

#include "server_aggregation.h"
#include "server_disk_manager.h"
#include "server_database_manager.h"
#include "errors.h"

server_error_t sum_encrypted_data_i(uint8_t* encrypted_aggregation_msg,
                         uint32_t encrypted_aggregation_msg_size,
                         uint8_t* publisher_key, 
                         uint8_t* storage_key, 
                         uint8_t** data_array, 
                         uint32_t data_count, 
                         char* pk,
                         uint8_t* result,
                         uint32_t* result_size) 
{

    Timer t("sum_encrypted_data_i");

    sample_status_t encryption_ret = SAMPLE_SUCCESS;

    // Decrypt publisher data

    if(DEBUG_PRINT) printf("\nDecrypting message\n");

    uint32_t publisher_data_size = MAX_DATA_SIZE;
    uint8_t* publisher_data = (uint8_t*)malloc((size_t)publisher_data_size);
    encryption_ret  = decrypt_data(publisher_key, 
                        encrypted_aggregation_msg, 
                        encrypted_aggregation_msg_size, 
                        publisher_data,
                        &publisher_data_size);
    if(encryption_ret != SAMPLE_SUCCESS) {
        free(publisher_data);
        return print_error_message(MESSAGE_DECRYPTION_ERROR);
    }

    if(DEBUG_PRINT) printf("%s\n", (char*)publisher_data);

    // Pick publisher access permissions
    // pk|72d41281|type|weg_multimeter|payload|250|permission1|72d41281
    char* access_permissions = (char*)malloc(1+publisher_data_size);
    memcpy(access_permissions, publisher_data, publisher_data_size);
    access_permissions[publisher_data_size] = '\0';
    free(publisher_data);
    
    int i = 0;
    char* p_access_permissions = &access_permissions[0];
    char* token = strtok_r(p_access_permissions, "|", &p_access_permissions);
    while (token != NULL && i<5) {
        token = strtok_r(NULL, "|", &p_access_permissions);
        i++;
    }

    uint32_t client_data_size = MAX_DATA_SIZE;
    uint8_t* client_data = (uint8_t*)malloc((size_t)client_data_size);

    // Iterate over data array
    if(DEBUG_PRINT) printf("\nDecrypting collected datas\n");

    unsigned long total = 0;
    for (uint32_t index = 0; index < data_count; index++) {

        // Separate parameters of stored data
        stored_data_t stored_data;
        get_stored_parameters((char*)(data_array[index]),&stored_data);

        // Decrypt data
        encryption_ret = decrypt_data(storage_key,
                           stored_data.encrypted,
                           stored_data.encrypted_size,
                           client_data,
                           &client_data_size);
        if(encryption_ret != SAMPLE_SUCCESS) {
            free(client_data);
            free(access_permissions);
            return print_error_message(DATA_DECRYPTION_ERROR);
        }

        /*
        char* client_data_clone = (char*)malloc(MAX_DATA_SIZE*sizeof(char));
        memcpy(client_data_clone,client_data,MAX_DATA_SIZE*sizeof(char));
        printf("%s\n", client_data_clone);
        */

       // Verify if publisher can access this data
        // pk|72d41281|type|weg_multimeter|payload|250|permission1|72d41281
       char auxiliar_client_data [1 + stored_data.encrypted_size * sizeof(char)];
       memcpy(auxiliar_client_data, client_data, client_data_size);
       auxiliar_client_data[client_data_size] = '\0';

       char payload[MAX_PAYLOAD_SIZE+1];
       unsigned long numeric_payload = 0;

       int permission_count = 0;
       bool accepted = false;
       i = 0;
       char* p_auxiliar_client_data = &auxiliar_client_data[0];
       token = strtok_r(p_auxiliar_client_data, "|", &p_auxiliar_client_data);
       while (token != NULL && accepted == false)
        {
            i++;
            token = strtok_r(NULL, "|", &p_auxiliar_client_data);
            if (i == 7+2*permission_count) {
                if(!memcmp(token, pk, 8))
                    accepted = true;
                permission_count++;
            }

            // Save payload in memory
            if (i == 5) { 

                unsigned j=0;
                while(token[j] != '|' && j<MAX_PAYLOAD_SIZE) { 
                    payload[j] = token[j];
                    j++;
                }
                payload[j] = 0; 

                char* invalid_char;
                numeric_payload = strtoul(payload, &invalid_char, 10);

                if(payload != 0 && *invalid_char != 0) {
                    free(client_data);
                    free(access_permissions);
                    return print_error_message(INVALID_PAYLOAD_ERROR);
                }
            }
        }

        // Update total
        if(accepted)
            total += numeric_payload;

        memset(client_data,0,MAX_DATA_SIZE*sizeof(uint8_t));
        client_data_size = MAX_DATA_SIZE*sizeof(uint8_t);
    }
    free(client_data);

    // Build plaintext aggregation data
    *result_size = (uint32_t)MAX_DATA_SIZE*sizeof(char*);
    char* aggregation_data = (char*)malloc((size_t)*result_size);
    sprintf(aggregation_data, "pk|%s|type|555555|payload|%lu|%s", (char*)pk, total, p_access_permissions);
    size_t aggregation_data_size = strlen(aggregation_data);
    free(access_permissions);

    if(DEBUG_PRINT) printf("Aggreagtion data: %s\n", aggregation_data);

    if(DEBUG_PRINT) printf("\nEncrypting aggreagtion data\n");

    // Encrypt aggregation data
    encryption_ret = encrypt_data(storage_key,
                       result,
                       result_size,
                       (uint8_t*)aggregation_data,
                       (uint32_t)aggregation_data_size);
    free(aggregation_data);
    if(encryption_ret != SAMPLE_SUCCESS) 
        return print_error_message(DATA_ENCRYPTION_ERROR);

    //quick_decrypt_debug(key, result, *result_size);
    return OK;
}

server_error_t get_db_request_i(iot_message_t rcv_msg, uint8_t* key, char* db_command) {

    Timer t("get_db_request_i");

    // Decrypt publisher data to get the DB request
    if(DEBUG_PRINT) printf("\nDecrypting publisher message\n");

    uint32_t publisher_data_size = MAX_DATA_SIZE;
    uint8_t* publisher_data = (uint8_t*)malloc((size_t)publisher_data_size+1);

    sample_status_t decrypt_ret = SAMPLE_SUCCESS;
    decrypt_ret  = decrypt_data(key, 
                        rcv_msg.encrypted, 
                        rcv_msg.encrypted_size, 
                        publisher_data,
                        &publisher_data_size);
    if(decrypt_ret != SAMPLE_SUCCESS) {
        free(publisher_data);
        return print_error_message(MESSAGE_DECRYPTION_ERROR);
    }

    // Verify if the client owns the key
    // Verify if pks are equals
    if(strncmp(rcv_msg.pk, (char*)publisher_data+3, 8)){
        free(publisher_data);
        return print_error_message(AUTHENTICATION_ERROR);
    }

    publisher_data[publisher_data_size] = 0;
    if(DEBUG_PRINT) printf("%s\n", (char*)publisher_data);

    // Get DB request
    if(DEBUG_PRINT) printf("\nSeparating DB request embeded inside decrypted message\n");

    int i = 0;
    char* publisher_data_string = (char*)publisher_data;
    char* token = strtok_r(publisher_data_string, "|", &publisher_data_string);
    while (token != NULL) {
        i++;
        token = strtok_r(NULL, "|", &publisher_data_string);

        if(i == 5) 
            strcpy(db_command, token);
    }
    
    if(DEBUG_PRINT) printf("DB command: %s\n", db_command);

    free(publisher_data);

    return OK;
} 
