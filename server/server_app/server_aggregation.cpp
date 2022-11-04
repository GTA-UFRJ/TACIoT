/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Description: aggregate client data
 */

#include "server_aggregation.h"
#include "server_disk_manager.h"


int sum_encrypted_data_i(uint8_t* encrypted_aggregation_msg,
                         uint32_t encrypted_aggregation_msg_size,
                         uint8_t* key, 
                         uint8_t** data_array, 
                         uint32_t* size_array, 
                         uint32_t data_count, 
                         char* pk,
                         uint8_t* result,
                         uint32_t* result_size) 
{

    Timer t("sum_encrypted_data_i");

    sample_status_t ret = SAMPLE_SUCCESS;

    // Decrypt publisher data

    if(DEBUG) printf("Decrypting message\n");

    uint32_t publisher_data_size = MAX_DATA_SIZE*sizeof(uint8_t);
    uint8_t* publisher_data = (uint8_t*)malloc((size_t)publisher_data_size);
    ret  = decrypt_data(key, 
                        encrypted_aggregation_msg, 
                        encrypted_aggregation_msg_size, 
                        publisher_data,
                        &publisher_data_size);
    if(ret != SAMPLE_SUCCESS) {
        printf("\n(ins) Error decrypting publisher data for aggregation\n");
        free(publisher_data);
        return -1;
    }

    if(DEBUG) printf("Decrypted publisher data: %s\n", (char*)publisher_data);

    // Pick publisher access permissions
    // pk|72d41281|type|weg_multimeter|payload|250|permission1|72d41281
    char access_permissions [1+publisher_data_size*sizeof(char)];
    memcpy(access_permissions, publisher_data, publisher_data_size);
    access_permissions[publisher_data_size] = '\0';
    
    int i = 0;
    char* p_access_permissions = &access_permissions[0];
    char* token = strtok_r(p_access_permissions, "|", &p_access_permissions);
    while (token != NULL && i<5) {
        token = strtok_r(NULL, "|", &p_access_permissions);
        i++;
    }
    
    free(publisher_data);
    uint32_t client_data_size = MAX_DATA_SIZE*sizeof(uint8_t);
    uint8_t* client_data = (uint8_t*)malloc((size_t)client_data_size);

    // Iterate over data array
    if(DEBUG) printf("Decrypting collected datas\n");

    unsigned long total = 0;
    for (uint32_t index = 0; index < data_count; index++) {

        // Decrypt data
        ret = decrypt_data(key,
                           data_array[index],
                           size_array[index],
                           client_data,
                           &client_data_size);
        if(ret != SAMPLE_SUCCESS) {
            printf("\n(ins) Error decrypting client data for aggregation\n");
            free(client_data);
            return -1;
        }

        /*
        char* client_data_clone = (char*)malloc(MAX_DATA_SIZE*sizeof(char));
        memcpy(client_data_clone,client_data,MAX_DATA_SIZE*sizeof(char));
        printf("%s\n", client_data_clone);
        */

       // Verify if publisher can access this data
        // pk|72d41281|type|weg_multimeter|payload|250|permission1|72d41281
       char auxiliar_client_data [1+size_array[index]*sizeof(char)];
       memcpy(auxiliar_client_data, client_data, size_array[index]);
       auxiliar_client_data[size_array[index]] = '\0';

       char payload[4];
       unsigned long numeric_payload = 0;

       int permission_count = 0;
       bool accepted = false;
       int i = 0;
       char* p_auxiliar_client_data = &auxiliar_client_data[0];
       char* token = strtok_r(p_auxiliar_client_data, "|", &p_auxiliar_client_data);
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
                memcpy(payload, token, 3);

                char* invalid_char;
                numeric_payload = strtoul(payload, &invalid_char, 10);

                if(payload != 0 && *invalid_char != 0) {
                    printf("\n(ins) Invalid plaintext client data format.\n");
                    free(client_data);
                    return -1;
                }
            }
        }

        // Update total
        if(accepted)
            total += numeric_payload;

        memset(client_data,0,MAX_DATA_SIZE*sizeof(uint8_t));
    }
    free(client_data);

    // Build plaintext aggregation data
    *result_size = (uint32_t)MAX_DATA_SIZE*sizeof(char*);
    char* aggregation_data = (char*)malloc((size_t)*result_size);
    sprintf(aggregation_data, "pk|%s|type|555555|payload|%lu|%s", (char*)pk, total, p_access_permissions);
    size_t aggregation_data_size = strlen(aggregation_data);

    if(DEBUG) printf("Aggreagtion data: %s\n", aggregation_data);

    ret = encrypt_data(key,
                       result,
                       result_size,
                       (uint8_t*)aggregation_data,
                       aggregation_data_size);
    if(ret != SAMPLE_SUCCESS) {
        printf("\n(ins) Error encrypting data for aggregation\n");
        free(client_data);
        free(aggregation_data);
        return -1;
    }
    free(aggregation_data);

    //quick_decrypt_debug(key, result, *result_size);
    return 0;
}



int get_aggregation_datas(char* pk, uint8_t** datas, uint32_t* sizes, uint32_t data_count, uint32_t* p_filtered_data_count) {

    // Read all data in file
    char* data = (char *)malloc(MAX_DATA_SIZE*sizeof(char));
    memset(data, 0, MAX_DATA_SIZE*sizeof(char));

    *p_filtered_data_count = 0;
    uint32_t offset = 0;
    for(uint32_t index=0; index < data_count; index++) {
        file_read(offset, data);
        stored_data_t stored_data;
        if(get_stored_parameters(data, &stored_data)) {
            free(data);
            free(datas);
            return -1;
        }
        //printf("%02x\n",(int)stored_data.encrypted_size);
        //printf("%s\n",stored_data.pk);
        //printf("%s\n",stored_data.type);

        memset(data, 0, MAX_DATA_SIZE*sizeof(char));
        offset += 5+7+3+9+5+5+10+stored_data.encrypted_size*3+1;

        // Filter energy consumption data from this client
        datas[*p_filtered_data_count] = (uint8_t*)malloc(stored_data.encrypted_size*sizeof(uint8_t*));
        if(strcmp(stored_data.type, "123456") == 0 && strcmp(pk, stored_data.pk) == 0) {
            memcpy(datas[*p_filtered_data_count], stored_data.encrypted, stored_data.encrypted_size);
            sizes[*p_filtered_data_count] = stored_data.encrypted_size;
            (*p_filtered_data_count)++;
        }
    }
    free(data);
}