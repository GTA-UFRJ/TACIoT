/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Description: codes for processing data
 */

#include "server_processing.h"
#include "server_disk_manager.h"
#include "server_database_manager.h"

//const sample_aes_gcm_128bit_key_t formatted_key[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}; 

int no_processing_s(iot_message_t rcv_msg, sgx_enclave_id_t global_eid, uint8_t* processed_data, uint32_t* p_real_size)
{
    Timer t("no_processing_s");

    // Search user file and read sealed key
    char seal_path[PATH_MAX_SIZE];
    sprintf(seal_path, "%s/%s", SEALS_PATH, rcv_msg.pk);

    size_t sealed_size = sizeof(sgx_sealed_data_t) + sizeof(uint8_t)*16;
    uint8_t* sealed_data = (uint8_t*)malloc(sealed_size);

    if(DEBUG) printf("Reading key file: %s\n", seal_path);

    FILE* seal_file = fopen(seal_path, "rb");
    if (seal_file == NULL) {
        printf("\nFailed to open the seal file \"%s\".\n", seal_path);
        free(sealed_data);
        return -1;
    }
    else {
        fread(sealed_data,1,sealed_size,seal_file);
        fclose(seal_file);
    }

    // Call enclave to unseal key, decrypt with the key, process and return encrypted result
    sgx_status_t ecall_status;
    sgx_status_t sgx_status;

    if(DEBUG) printf("Entering enclave\n");

    sgx_status = process_data(global_eid, &ecall_status,
        (sgx_sealed_data_t*)sealed_data,            //sealed key 
        rcv_msg.encrypted,                          //data for being decrypted and processed 
        rcv_msg.encrypted_size,                     //encrypted data size
        processed_data,                             //data for being published
        (uint32_t)RESULT_MAX_SIZE,                  //buffer max size with data for publication
        p_real_size                                 //data real size           
    );

    if(DEBUG) printf("Exiting enclave\n");

    if(sgx_status != SGX_SUCCESS || ecall_status != SGX_SUCCESS) {
        printf("\n(sec) Enclave problem inside no_processing_s():\n"); 
        if(sgx_status == 0x5001)
            printf("Insuficient buffer size.\n");
        else
            printf("SGX error codes %d, %d\n", (int)sgx_status, (int)ecall_status);
        return -1;
    }
    return 0;
}


int no_processing(iot_message_t rcv_msg, sgx_enclave_id_t global_eid, bool secure) 
{
    // Thread open dedicated database connection 
    sqlite3 *db;

    if(DEBUG) printf("Opening dabase\n"); 

    if(sqlite3_open(DATABASE_PATH, &db)) {
       printf("Can't open database: %s\n", sqlite3_errmsg(db));
       return -1;
    } 

    Timer t("no_processing");
    if(secure == false) {

        if(database_write(db,rcv_msg)) 
            return -1;

    }
    else {
        uint8_t processed_data [RESULT_MAX_SIZE];
        uint32_t real_size;
        if(no_processing_s(rcv_msg, global_eid, processed_data, &real_size)) {
            return -1;
        }

        if(database_write(db,rcv_msg)) 
            return -1;
    }

    // Close connection to database
    sqlite3_close(db);

    return 0;
}

int aggregation_i(sqlite3* db, iot_message_t rcv_msg, uint8_t* processed_data, uint32_t* p_real_size) {

    Timer t("aggregation_i");

    // Search user file and read plain key
    char seal_path[PATH_MAX_SIZE];
    sprintf(seal_path, "%s/%s_i", SEALS_PATH, rcv_msg.pk);

    size_t key_size = sizeof(uint8_t)*16;
    uint8_t* key = (uint8_t*)malloc(key_size);

    if(DEBUG) printf("Opening file: %s\n", seal_path);

    FILE* plain_key_file = fopen(seal_path, "r");
    if (plain_key_file == NULL) {
        printf("\nWarning: Failed to open the plain key file \"%s\".\n", seal_path);
        free(key);
        return 1;
    }
    else {
        fread(key,1,key_size,plain_key_file);
        fclose(plain_key_file);
    }

    // Get DB request
    char db_command[MAX_DB_COMMAND_SIZE];

    if(get_db_request_i(rcv_msg, key, db_command)){
        free(key);
        return -1;
    }

    // Create arrays for datas and datas sizes 
    char** datas = (char**)malloc(MAX_NUM_DATAS_QUERIED*sizeof(char*)); 
    uint32_t* datas_sizes = (uint32_t*)malloc(MAX_NUM_DATAS_QUERIED*sizeof(uint32_t)); 
    uint32_t filtered_data_count = 0;

    // Coleect data for aggregation
    if(database_read(db, db_command, datas, datas_sizes, &filtered_data_count)) {
        free(key);
        free_data_array(datas, datas_sizes, filtered_data_count);
        return -1;
    }

    // Call function to aggregate 
    // pk|72d41281|type|weg_multimeter|payload|250110090|permission1|72d41281
    if(sum_encrypted_data_i(rcv_msg.encrypted,
                            rcv_msg.encrypted_size,
                            key, 
                            (uint8_t**)datas, 
                            filtered_data_count, 
                            rcv_msg.pk, 
                            processed_data, 
                            p_real_size)) {
        free_data_array(datas, datas_sizes, filtered_data_count);
        free(key);
        return -1;
    }
    free_data_array(datas, datas_sizes, filtered_data_count);
    free(key);

    return 0;
}

int aggregation_s(sqlite3* db, iot_message_t rcv_msg, uint8_t* processed_data, sgx_enclave_id_t global_eid, uint32_t* p_real_size) 
{ 
    Timer t("aggregation_s");

    // Search user file and read sealed key
    char seal_path[PATH_MAX_SIZE];
    sprintf(seal_path, "%s/%s", SEALS_PATH, rcv_msg.pk);

    size_t sealed_key_size = sizeof(sgx_sealed_data_t) + sizeof(uint8_t)*16;
    uint8_t* sealed_key = (uint8_t*)malloc(sealed_key_size);

    if(DEBUG) printf("Opening file: %s\n", seal_path);

    FILE* seal_file = fopen(seal_path, "rb");
    if (seal_file == NULL) {
        printf("\nWarning: Failed to open the seal file \"%s\".\n", seal_path);
        free(sealed_key);
        return 1;
    }
    else {
        fread(sealed_key,1,sealed_key_size,seal_file);
        fclose(seal_file);
    }

    // Get DB request
    char db_command[MAX_DB_COMMAND_SIZE];

    sgx_status_t sgx_status;
    sgx_status_t ecall_status;
    {
    Timer t2("sum_encrypted_data_s");

    if(DEBUG) printf("Entering enclave\n");

    sgx_status = get_db_request_s(global_eid, &ecall_status, 
                        rcv_msg.encrypted, 
                        rcv_msg.encrypted_size, 
                        MAX_DB_COMMAND_SIZE,
                        (sgx_sealed_data_t*)sealed_key, 
                        db_command);
    
    if(DEBUG) printf("Exiting enclave\n");

    if(sgx_status != SGX_SUCCESS || ecall_status != SGX_SUCCESS) {
        printf("\n(sec) Enclave problem inside aggregation_s():\n");
        if(sgx_status == 0x5001)
            printf("Insuficient result buffer size.");
        else if(sgx_status == 0x5003)
            printf("\n(ins) Invalid plaintext client data format.\n");
        else
            printf("SGX error codes %d, %d\n", (int)sgx_status, (int)ecall_status);
        free(sealed_key);
        return -1;
    }
    }

    // Create arrays for datas and datas sizes 
    char** datas = (char**)malloc(MAX_NUM_DATAS_QUERIED*sizeof(char*)); 
    uint32_t* datas_sizes = (uint32_t*)malloc(MAX_NUM_DATAS_QUERIED*sizeof(uint32_t)); 
    uint32_t filtered_data_count = 0;

    // Coleect data for aggregation
    if(database_read(db, db_command, datas, datas_sizes, &filtered_data_count)) {
        free(sealed_key);
        free_data_array(datas, datas_sizes, filtered_data_count);
        return -1;
    }

    // Call function to aggregate 
    // pk|72d41281|type|weg_multimeter|payload|250110090|permission1|72d41281
    {
    Timer t3("sum_encrypted_data_s");

    if(DEBUG) printf("Entering enclave\n");
    sgx_status = sum_encrypted_data_s(global_eid, &ecall_status,
            rcv_msg.encrypted,
            rcv_msg.encrypted_size,
            (sgx_sealed_data_t*)sealed_key, 
            (uint8_t**)datas, 
            filtered_data_count,
            rcv_msg.pk,
            MAX_DATA_SIZE,
            processed_data,
            p_real_size);
    if(DEBUG) printf("Exiting enclave\n");

    if(sgx_status != SGX_SUCCESS || ecall_status != SGX_SUCCESS) {
        printf("\n(sec) Enclave problem inside aggregation_s():\n");
        if(sgx_status == 0x5001)
            printf("Insuficient result buffer size.");
        else if(sgx_status == 0x5003)
            printf("\n(ins) Invalid plaintext client data format.\n");
        else
            printf("SGX error codes %d, %d\n", (int)sgx_status, (int)ecall_status);
        free(sealed_key);
        free_data_array((char**)datas, datas_sizes, filtered_data_count);
        return -1;
    }
    }
    free_data_array((char**)datas, datas_sizes, filtered_data_count);
    free(sealed_key);
    
    return 0;
}

int aggregation(iot_message_t rcv_msg, sgx_enclave_id_t global_eid, bool secure) 
{
    Timer t("aggregation");

    // Thread open dedicated database connection 
    sqlite3 *db;

    if(DEBUG) printf("Opening dabase\n"); 

    if(sqlite3_open(DATABASE_PATH, &db)) {
       printf("Can't open database: %s\n", sqlite3_errmsg(db));
       return -1;
    } 

    uint8_t processed_data [RESULT_MAX_SIZE];
    uint32_t real_size;
    if(secure == false) {
        if(aggregation_i(db, rcv_msg, processed_data, &real_size)) {
            
            // Close connection to database
            sqlite3_close(db);

            return -1;
        }
    }
    else {
        if(aggregation_s(db, rcv_msg, processed_data, global_eid, &real_size)) {
                
            // Close connection to database
            sqlite3_close(db);

            return -1;
        }
    }

    // Write data in file
    iot_message_t data_for_writing;
    memcpy(data_for_writing.pk, rcv_msg.pk, 9);
    sprintf(data_for_writing.type, "555555");
    data_for_writing.encrypted_size = real_size;    
    data_for_writing.encrypted = (uint8_t*)malloc(real_size);
    memcpy(data_for_writing.encrypted, processed_data, real_size);

    if(database_write(db, data_for_writing)) {
        printf("Failed to publish message (aggregation).\n");
        free(data_for_writing.encrypted);
        
        // Close connection to database
        sqlite3_close(db);
        
        return -1;
    }
    free(data_for_writing.encrypted);

    // Close connection to database
    sqlite3_close(db);

    return 0;
}