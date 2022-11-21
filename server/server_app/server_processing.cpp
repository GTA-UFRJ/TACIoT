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
    char publisher_seal_path[PATH_MAX_SIZE];
    sprintf(publisher_seal_path, "%s/%s", SEALS_PATH, rcv_msg.pk);

    size_t publisher_sealed_size = sizeof(sgx_sealed_data_t) + sizeof(uint8_t)*16;
    uint8_t* publisher_sealed_data = (uint8_t*)malloc(publisher_sealed_size);

    if(DEBUG) printf("Reading publisher key file: %s\n", publisher_seal_path);

    FILE* publisher_seal_file = fopen(publisher_seal_path, "rb");
    if (publisher_seal_file == NULL) {
        printf("\nFailed to open the seal file \"%s\".\n", publisher_seal_path);
        free(publisher_sealed_data);
        return -1;
    }
    else {
        fread(publisher_sealed_data,1,publisher_sealed_size,publisher_seal_file);
        fclose(publisher_seal_file);
    }

    // Search server file and read sealed key
    char storage_seal_path[PATH_MAX_SIZE];
    sprintf(storage_seal_path, "%s/storage_key", SEALS_PATH);

    size_t storage_sealed_size = sizeof(sgx_sealed_data_t) + sizeof(uint8_t)*16;
    uint8_t* storage_sealed_data = (uint8_t*)malloc(storage_sealed_size);

    if(DEBUG) printf("Reading storage key file: %s\n", storage_seal_path);

    FILE* storage_seal_file = fopen(storage_seal_path, "rb");
    if (storage_seal_file == NULL) {
        printf("\nFailed to open the seal file \"%s\".\n", storage_seal_path);
        free(publisher_sealed_data);
        free(storage_sealed_data);
        return -1;
    }
    else {
        fread(storage_sealed_data,1,storage_sealed_size,storage_seal_file);
        fclose(storage_seal_file);
    }

    // Call enclave to unseal key, decrypt with the key, process and return encrypted result
    sgx_status_t ecall_status;
    sgx_status_t sgx_status;

    if(DEBUG) printf("Entering enclave\n");

    sgx_status = process_data(global_eid, &ecall_status,
        (sgx_sealed_data_t*)publisher_sealed_data,  //sealed key 
        (sgx_sealed_data_t*)storage_sealed_data,    //sealed key 
        rcv_msg.encrypted,                          //data for being decrypted and processed 
        rcv_msg.encrypted_size,                     //encrypted data size
        processed_data,                             //data for being published
        (uint32_t)RESULT_MAX_SIZE,                  //buffer max size with data for publication
        p_real_size                                 //data real size           
    );

    if(DEBUG) printf("Exiting enclave\n");

    if(sgx_status != SGX_SUCCESS || ecall_status != SGX_SUCCESS) {

        free(publisher_sealed_data);
        free(storage_sealed_data);

        printf("\n(sec) Enclave problem inside no_processing_s():\n"); 
        if(sgx_status == 0x5001)
            printf("Insuficient buffer size.\n");
        else
            printf("SGX error codes %d, %d\n", (int)sgx_status, (int)ecall_status);
        return -1;
    }
    free(publisher_sealed_data);
    free(storage_sealed_data);

    return 0;
}


int no_processing_i(iot_message_t rcv_msg, uint8_t* processed_data, uint32_t* p_real_size)
{
    Timer t("no_processing_i");

    // Search user file and read key
    char publihser_key_path[PATH_MAX_SIZE];
    sprintf(publihser_key_path, "%s/%s_i", SEALS_PATH, rcv_msg.pk);

    size_t publisher_key_size = 16;
    uint8_t* publisher_key = (uint8_t*)malloc(publisher_key_size);

    if(DEBUG) printf("Reading publisher key file: %s\n", publihser_key_path);

    FILE* publisher_key_file = fopen(publihser_key_path, "rb");
    if (publisher_key_file == NULL) {
        printf("\nFailed to open the seal file \"%s\".\n", publihser_key_path);
        free(publisher_key);
        return -1;
    }
    else {
        fread(publisher_key,1,publisher_key_size,publisher_key_file);
        fclose(publisher_key_file);
    }

    // Search server file and read storage key
    char storage_key_path[PATH_MAX_SIZE];
    sprintf(storage_key_path, "%s/storage_key_i", SEALS_PATH);

    size_t storage_key_size = 16;
    uint8_t* storage_key = (uint8_t*)malloc(storage_key_size);

    if(DEBUG) printf("Reading storage key file: %s\n", storage_key_path);

    FILE* storage_key_file = fopen(storage_key_path, "rb");
    if (storage_key_file == NULL) {
        printf("\nFailed to open the seal file \"%s\".\n", storage_key_path);
        free(publisher_key);
        free(storage_key);
        return -1;
    }
    else {
        fread(storage_key,1,storage_key_size,storage_key_file);
        fclose(storage_key_file);
    }

    // Decrypt publisher data with publihser key
    if(DEBUG) printf("Decrypting publisher data\n");

    uint32_t decrypted_data_size = MAX_DATA_SIZE;
    uint8_t* decrypted_data = (uint8_t*)malloc(decrypted_data_size);

    sample_status_t ret; 
    ret = decrypt_data(publisher_key,
                       rcv_msg.encrypted,
                       rcv_msg.encrypted_size,
                       decrypted_data,
                       &decrypted_data_size);
    if(ret != SAMPLE_SUCCESS) {
        printf("\n(ins) Error decrypting publisher data\n");
        free(publisher_key);
        free(storage_key);
        free(decrypted_data);
        return -1;
    }
    free(publisher_key);

    // Encrypt plaintext publihser data with storage key
    if(DEBUG) printf("Encrypting publisher data\n");

    uint32_t encrypted_data_size = rcv_msg.encrypted_size;
    uint8_t* encrypted_data = (uint8_t*)malloc(encrypted_data_size);

    ret = encrypt_data(storage_key,
                       rcv_msg.encrypted,
                       &encrypted_data_size,
                       decrypted_data,
                       decrypted_data_size);
    if(ret != SAMPLE_SUCCESS) {
        printf("\n(ins) Error encrypting publisher data\n");
        free(storage_key);
        free(decrypted_data);
        free(encrypted_data);
        return -1;
    }
    free(storage_key);
    free(decrypted_data);

    // Copy result to parameters
    if(encrypted_data_size > MAX_DATA_SIZE) {
        printf("(ins) Insuficient memory for encrypted result\n");
        free(encrypted_data);
        return -1;
    }

    *p_real_size = encrypted_data_size;
    memcpy(processed_data, encrypted_data, encrypted_data_size);
    free(encrypted_data);
    
    return 0;
}


int no_processing(iot_message_t rcv_msg, sgx_enclave_id_t global_eid, bool secure) 
{
    Timer t("no_processing");

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
        if(no_processing_i(rcv_msg, processed_data, &real_size)) {
            // Close connection to database
            sqlite3_close(db);
            return -1;
        }

        if(database_write(db,rcv_msg)) {
            // Close connection to database
            sqlite3_close(db);
            return -1;
        }

    }
    else {
        if(no_processing_s(rcv_msg, global_eid, processed_data, &real_size)) {
            // Close connection to database
            sqlite3_close(db);
            return -1;
        }

        if(database_write(db,rcv_msg)) {
            // Close connection to database
            sqlite3_close(db);
            return -1;
        }
    }

    // Close connection to database
    sqlite3_close(db);

    return 0;
}

int aggregation_s(sqlite3* db, iot_message_t rcv_msg, uint8_t* processed_data, sgx_enclave_id_t global_eid, uint32_t* p_real_size) 
{ 
    Timer t("aggregation_s");

    // Search user file and read sealed key
    char publisher_seal_path[PATH_MAX_SIZE];
    sprintf(publisher_seal_path, "%s/%s", SEALS_PATH, rcv_msg.pk);

    size_t publisher_sealed_size = sizeof(sgx_sealed_data_t) + sizeof(uint8_t)*16;
    uint8_t* publisher_sealed_data = (uint8_t*)malloc(publisher_sealed_size);

    if(DEBUG) printf("Reading publisher key file: %s\n", publisher_seal_path);

    FILE* publisher_seal_file = fopen(publisher_seal_path, "rb");
    if (publisher_seal_file == NULL) {
        printf("\nFailed to open the seal file \"%s\".\n", publisher_seal_path);
        free(publisher_sealed_data);
        return -1;
    }
    else {
        fread(publisher_sealed_data,1,publisher_sealed_size,publisher_seal_file);
        fclose(publisher_seal_file);
    }

    // Search server file and read sealed key
    char storage_seal_path[PATH_MAX_SIZE];
    sprintf(storage_seal_path, "%s/storage_key", SEALS_PATH);

    size_t storage_sealed_size = sizeof(sgx_sealed_data_t) + sizeof(uint8_t)*16;
    uint8_t* storage_sealed_data = (uint8_t*)malloc(storage_sealed_size);

    if(DEBUG) printf("Reading storage key file: %s\n", storage_seal_path);

    FILE* storage_seal_file = fopen(storage_seal_path, "rb");
    if (storage_seal_file == NULL) {
        printf("\nFailed to open the seal file \"%s\".\n", storage_seal_path);
        free(publisher_sealed_data);
        free(storage_sealed_data);
        return -1;
    }
    else {
        fread(storage_sealed_data,1,storage_sealed_size,storage_seal_file);
        fclose(storage_seal_file);
    }

    // Get DB request
    char db_command[MAX_DB_COMMAND_SIZE];

    sgx_status_t sgx_status;
    sgx_status_t ecall_status;
    {
    Timer t2("get_db_request_s");

    if(DEBUG) printf("Entering enclave\n");

    sgx_status = get_db_request_s(global_eid, &ecall_status, 
                        rcv_msg.encrypted, 
                        rcv_msg.encrypted_size, 
                        MAX_DB_COMMAND_SIZE,
                        (sgx_sealed_data_t*)publisher_seal_file, 
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
        free(publisher_sealed_data);
        free(storage_sealed_data);
        return -1;
    }
    }

    // Create arrays for datas and datas sizes 
    char** datas = (char**)malloc(MAX_NUM_DATAS_QUERIED*sizeof(char*)); 
    uint32_t* datas_sizes = (uint32_t*)malloc(MAX_NUM_DATAS_QUERIED*sizeof(uint32_t)); 
    uint32_t filtered_data_count = 0;

    // Coleect data for aggregation
    if(database_read(db, db_command, datas, datas_sizes, &filtered_data_count)) {
        free(publisher_sealed_data);
        free(storage_sealed_data);
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
            (sgx_sealed_data_t*)publisher_sealed_data, 
            (sgx_sealed_data_t*)storage_sealed_data, 
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
        free(publisher_sealed_data);
        free(storage_sealed_data);
        free_data_array((char**)datas, datas_sizes, filtered_data_count);
        return -1;
    }
    }
    free(publisher_sealed_data);
    free(storage_sealed_data);
    free_data_array((char**)datas, datas_sizes, filtered_data_count);
    
    return 0;
}

int aggregation_i(sqlite3* db, iot_message_t rcv_msg, uint8_t* processed_data, uint32_t* p_real_size) {

    Timer t("aggregation_i");

    // Search user file and read key
    char publihser_key_path[PATH_MAX_SIZE];
    sprintf(publihser_key_path, "%s/%s_i", SEALS_PATH, rcv_msg.pk);

    size_t publisher_key_size = 16;
    uint8_t* publisher_key = (uint8_t*)malloc(publisher_key_size);

    if(DEBUG) printf("Reading publisher key file: %s\n", publihser_key_path);

    FILE* publisher_key_file = fopen(publihser_key_path, "rb");
    if (publisher_key_file == NULL) {
        printf("\nFailed to open the seal file \"%s\".\n", publihser_key_path);
        free(publisher_key);
        return -1;
    }
    else {
        fread(publisher_key,1,publisher_key_size,publisher_key_file);
        fclose(publisher_key_file);
    }

    // Search server file and read storage key
    char storage_key_path[PATH_MAX_SIZE];
    sprintf(storage_key_path, "%s/storage_key_i", SEALS_PATH);

    size_t storage_key_size = 16;
    uint8_t* storage_key = (uint8_t*)malloc(storage_key_size);

    if(DEBUG) printf("Reading storage key file: %s\n", storage_key_path);

    FILE* storage_key_file = fopen(storage_key_path, "rb");
    if (storage_key_file == NULL) {
        printf("\nFailed to open the seal file \"%s\".\n", storage_key_path);
        free(publisher_key);
        free(storage_key);
        return -1;
    }
    else {
        fread(storage_key,1,storage_key_size,storage_key_file);
        fclose(storage_key_file);
    }

    // Get DB request
    char db_command[MAX_DB_COMMAND_SIZE];

    if(get_db_request_i(rcv_msg, publisher_key, db_command)){
        free(publisher_key);
        free(storage_key);
        free(publisher_key);
        return -1;
    }

    // Create arrays for datas and datas sizes 
    char** datas = (char**)malloc(MAX_NUM_DATAS_QUERIED*sizeof(char*)); 
    uint32_t* datas_sizes = (uint32_t*)malloc(MAX_NUM_DATAS_QUERIED*sizeof(uint32_t)); 
    uint32_t filtered_data_count = 0;

    // Coleect data for aggregation
    if(database_read(db, db_command, datas, datas_sizes, &filtered_data_count)) {
        free(publisher_key);
        free(storage_key);
        free_data_array(datas, datas_sizes, filtered_data_count);
        return -1;
    }

    // Call function to aggregate 
    // pk|72d41281|type|weg_multimeter|payload|250110090|permission1|72d41281
    if(sum_encrypted_data_i(rcv_msg.encrypted,
                            rcv_msg.encrypted_size,
                            publisher_key,
                            storage_key, 
                            (uint8_t**)datas, 
                            filtered_data_count, 
                            rcv_msg.pk, 
                            processed_data, 
                            p_real_size)) {
        free_data_array(datas, datas_sizes, filtered_data_count);
        free(publisher_key);
        free(storage_key);
        return -1;
    }
    free_data_array(datas, datas_sizes, filtered_data_count);
    free(publisher_key);
    free(storage_key);

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