/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Description: codes for processing data
 */

#include "server_processing.h"
#include "server_disk_manager.h"

uint32_t no_processing_s(iot_message_t rcv_msg, sgx_enclave_id_t global_eid, uint8_t* processed_data){
    
    Timer t("no_processing_s");

    // Search user file and read sealed key
    char seal_path[PATH_MAX_SIZE];
    sprintf(seal_path, "%s/%s", SEALS_PATH, rcv_msg.pk);
    FILE* seal_file = fopen(seal_path, "rb");
    size_t sealed_size = sizeof(sgx_sealed_data_t) + sizeof(uint8_t)*16;
    uint8_t* sealed_data = (uint8_t*)malloc(sealed_size);
    if (seal_file == NULL) {
        printf("\nWarning: Failed to open the seal file \"%s\".\n", seal_path);
        fclose(seal_file);
        free(sealed_data);
        return 1;
    }
    else {
        fread(sealed_data,1,sealed_size,seal_file);
        fclose(seal_file);
    }

    // Call enclave to unseal key, decrypt with the key, process and return encrypted result
    sgx_status_t ecall_status;
    sgx_status_t sgx_status;
    uint32_t real_size;
    uint32_t decMessageLen = rcv_msg.encrypted_size - (SAMPLE_AESGCM_MAC_SIZE + SAMPLE_AESGCM_IV_SIZE);
    sgx_status = process_data(global_eid, &ecall_status,
        (sgx_sealed_data_t*)sealed_data,            //sealed key 
        rcv_msg.encrypted,                          //data for being decrypted and processed 
        rcv_msg.encrypted_size,                     //encrypted data size
        decMessageLen,                              //bufer size with decrypted data  
        processed_data,                             //data for being published
        (uint32_t)RESULT_MAX_SIZE,                  //buffer max size with data for being published
        &real_size                                  //data real size           
    );
    return real_size;
}


void no_processing(iot_message_t rcv_msg, sgx_enclave_id_t global_eid, bool secure) {
    if(secure == false) {
        file_write (rcv_msg, rcv_msg.encrypted, rcv_msg.encrypted_size);
    }
    else {
        uint8_t processed_data [RESULT_MAX_SIZE];
        uint32_t real_size = no_processing_s(rcv_msg, global_eid, processed_data);
        file_write (rcv_msg, processed_data, real_size);
    }
}

uint32_t aggregation_i(iot_message_t rcv_msg, uint8_t* processed_data) {

    Timer t("aggregation_i");

    // Search user file and read plain key
    char seal_path[PATH_MAX_SIZE];
    sprintf(seal_path, "%s/%s_i", SEALS_PATH, rcv_msg.pk);
    FILE* plain_file = fopen(seal_path, "r");
    size_t plain_size = sizeof(uint8_t)*16;
    uint8_t* plain_data = (uint8_t*)malloc(plain_size);
    if (plain_file == NULL) {
        printf("\nWarning: Failed to open the plain file \"%s\".\n", seal_path);
        fclose(plain_file);
        free(plain_data);
        return 1;
    }
    else {
        fread(plain_data,1,plain_size,plain_file);
        fclose(plain_file);
    }

    // Count number of lines in file
    uint32_t data_count = count_entries();

    // Create arrays for datas and datas sizes 
    uint8_t** datas = (uint8_t**)malloc(data_count*sizeof(uint8_t*)); 
    uint32_t* datas_sizes = (uint32_t*)malloc(data_count*sizeof(uint32_t)); 

    // Read all data in file
    char* data = (char *)malloc(MAX_DATA_SIZE*sizeof(char));
    uint32_t filtered_data_count = 0;
    for(uint32_t index=0; index < data_count; index++) {
        file_read(index, data);
        stored_data_t stored_data = get_stored_parameters(data);
        memset(data, 0, MAX_DATA_SIZE*sizeof(char));

        // Filter energy consumption data from this client
        if(stored_data.type == "123456" && strcmp(rcv_msg.pk, stored_data.pk)) {
            memcpy(datas[filtered_data_count], stored_data.encrypted, stored_data.encrypted_size);
            datas_sizes[filtered_data_count] = stored_data.encrypted_size;
        }
        filtered_data_count++;
    }

    // Call function to aggregate 
    // pk|72d41281|type|weg_multimeter|payload|250110090|permission1|72d41281
    unsigned long int result;
    //result = sum_encrypted_data(plain_data, datas, datas_sizes, filtered_data_count);

    // Print data for test
    // printf("Aggregated: %lu", result);


    // We will build this encryption section

    // Build encrypted data format
    //sprintf("pk|...")

    // Encrypt data (using sample_rijndael128GCM_encrypt from dynamic library)

    // Write data in file
    //file_write(rcv_msg, encrypted_data, encrypted_data_size);

}

void aggregation(iot_message_t rcv_msg, sgx_enclave_id_t global_eid, bool secure) {
    printf("Not finished yet!\n");
    /*
    if(secure == false) {
        uint8_t processed_data [RESULT_MAX_SIZE];
        uint32_t real_size = aggregation_i(rcv_msg, processed_data);
        file_write (rcv_msg, rcv_msg.encrypted, rcv_msg.encrypted_size);
        file_write (rcv_msg, processed_data, real_size);
    }
    else {
        uint8_t processed_data [RESULT_MAX_SIZE];
        uint32_t real_size = no_processing_s(rcv_msg, global_eid, processed_data);
        file_write (rcv_msg, processed_data, real_size);
    }*/
}