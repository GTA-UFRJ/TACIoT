/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Description: codes for processing data
 */

#include "server_processing.h"
#include "server_disk_manager.h"
#include "server_database_manager.h"
#include "errors.h"

//const sample_aes_gcm_128bit_key_t formatted_key[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}; 

server_error_t no_processing_s(iot_message_t rcv_msg, sgx_enclave_id_t global_eid, uint8_t* processed_data, uint32_t* p_real_size)
{
    Timer t("no_processing_s");

    // Search user file and read sealed key
    char* publisher_seal_path = (char*)malloc(PATH_MAX_SIZE);
    sprintf(publisher_seal_path, "%s/%s", SEALS_PATH, rcv_msg.pk);

    if(DEBUG) printf("\nReading publisher key file: %s\n", publisher_seal_path);

    FILE* publisher_seal_file = fopen(publisher_seal_path, "rb");
    free(publisher_seal_path);
    if (publisher_seal_file == NULL) 
        return print_error_message(OPEN_CLIENT_KEY_FILE_ERROR);
    
    size_t publisher_sealed_size = sizeof(sgx_sealed_data_t) + sizeof(uint8_t)*16;
    uint8_t* publisher_sealed_data = (uint8_t*)malloc(publisher_sealed_size);
    fread(publisher_sealed_data,1,publisher_sealed_size,publisher_seal_file);
    fclose(publisher_seal_file);

    // Search server file and read sealed key
    char* storage_seal_path = (char*)malloc(PATH_MAX_SIZE);
    sprintf(storage_seal_path, "%s/storage_key", SEALS_PATH);

    if(DEBUG) printf("\nReading storage key file: %s\n", storage_seal_path);

    FILE* storage_seal_file = fopen(storage_seal_path, "rb");
    free(storage_seal_path);
    if (storage_seal_file == NULL) {
        free(publisher_sealed_data);     
        return print_error_message(OPEN_SERVER_KEY_FILE_ERROR);
    }

    size_t storage_sealed_size = sizeof(sgx_sealed_data_t) + sizeof(uint8_t)*16;
    uint8_t* storage_sealed_data = (uint8_t*)malloc(storage_sealed_size);
    fread(storage_sealed_data,1,storage_sealed_size,storage_seal_file);
    fclose(storage_seal_file);

    // Call enclave to unseal key, decrypt with the key, process and return encrypted result
    sgx_status_t ecall_status;
    sgx_status_t sgx_status;

    {
    Timer t2("process_data");
    if(DEBUG) printf("\nEntering enclave for preparing data for publication\n");

    sgx_status = process_data(global_eid, &ecall_status,
        (sgx_sealed_data_t*)publisher_sealed_data,  //sealed key 
        (sgx_sealed_data_t*)storage_sealed_data,    //sealed key 
        rcv_msg.pk,                                 //pk
        rcv_msg.encrypted,                          //data for being decrypted and processed 
        rcv_msg.encrypted_size,                     //encrypted data size
        processed_data,                             //data for being published
        (uint32_t)RESULT_MAX_SIZE,                  //buffer max size with data for publication
        p_real_size                                 //data real size           
    );

    if(DEBUG) printf("Exiting enclave\n");

    free(publisher_sealed_data);    
    free(storage_sealed_data);

    if(sgx_status != SGX_SUCCESS || ecall_status != SGX_SUCCESS) {
        if(sgx_status == 0x5001) printf("Insuficient buffer size.\n");
        else printf("SGX error codes 0x%04x, 0x%04x\n", (int)sgx_status, (int)ecall_status);
        return print_error_message(NO_PROCESSING_ENCLAVE_ERROR);
    }
    }

    return OK;
}


server_error_t no_processing_i(iot_message_t rcv_msg, uint8_t* processed_data, uint32_t* p_real_size)
{
    Timer t("no_processing_i");

    // Search user file and read key
    char* publihser_key_path = (char*)malloc(PATH_MAX_SIZE);
    sprintf(publihser_key_path, "%s/%s_i", SEALS_PATH, rcv_msg.pk);

    if(DEBUG) printf("\nReading publisher key file: %s\n", publihser_key_path);

    FILE* publisher_key_file = fopen(publihser_key_path, "rb");
    free(publihser_key_path);
    if (publisher_key_file == NULL) 
        return print_error_message(OPEN_CLIENT_KEY_FILE_ERROR);

    size_t publisher_key_size = 16;
    uint8_t* publisher_key = (uint8_t*)malloc(publisher_key_size);
    fread(publisher_key,1,publisher_key_size,publisher_key_file);
    fclose(publisher_key_file);

    // Search server file and read storage key
    char* storage_key_path = (char*)malloc(PATH_MAX_SIZE);
    sprintf(storage_key_path, "%s/storage_key_i", SEALS_PATH);

    if(DEBUG) printf("\nReading storage key file: %s\n", storage_key_path);

    FILE* storage_key_file = fopen(storage_key_path, "rb");
    free(storage_key_path);
    if (storage_key_file == NULL) {
        free(publisher_key);
        return print_error_message(OPEN_SERVER_KEY_FILE_ERROR);
    }

    size_t storage_key_size = 16;
    uint8_t* storage_key = (uint8_t*)malloc(storage_key_size);
    fread(storage_key,1,storage_key_size,storage_key_file);
    fclose(storage_key_file);
    
    // Decrypt publisher data with publihser key
    if(DEBUG) printf("\nDecrypting publisher message\n");

    uint32_t decrypted_data_size = MAX_DATA_SIZE;
    uint8_t* decrypted_data = (uint8_t*)malloc(decrypted_data_size);

    sample_status_t encryption_ret; 
    encryption_ret = decrypt_data(publisher_key,
                       rcv_msg.encrypted,
                       rcv_msg.encrypted_size,
                       decrypted_data,
                       &decrypted_data_size);
    free(publisher_key);
    if(encryption_ret != SAMPLE_SUCCESS) {
        free(storage_key);
        free(decrypted_data);
        return print_error_message(MESSAGE_DECRYPTION_ERROR);
    }

    // Verify if the client owns the key
    // Verify if pks are equals
    if(strncmp(rcv_msg.pk, (char*)decrypted_data+3, 8)){
        free(decrypted_data);
        return print_error_message(AUTHENTICATION_ERROR);
    }

    // Encrypt plaintext publihser data with storage key
    if(DEBUG) printf("\nEncrypting publisher data\n");

    uint32_t encrypted_data_size = rcv_msg.encrypted_size;
    uint8_t* encrypted_data = (uint8_t*)malloc(encrypted_data_size);

    encryption_ret = encrypt_data(storage_key,
                       rcv_msg.encrypted,
                       &encrypted_data_size,
                       decrypted_data,
                       decrypted_data_size);
    free(storage_key);
    free(decrypted_data);
    if(encryption_ret != SAMPLE_SUCCESS) {
        free(encrypted_data);
        return print_error_message(DATA_ENCRYPTION_ERROR);
    }

    // Copy result to parameters
    if(encrypted_data_size > MAX_DATA_SIZE) {
        free(encrypted_data);
        return print_error_message(ENCRYPTED_OVERFLOW_ERROR);
    }

    *p_real_size = encrypted_data_size;
    memcpy(processed_data, encrypted_data, encrypted_data_size);
    free(encrypted_data);
    
    return OK;
}


server_error_t no_processing(iot_message_t rcv_msg, sgx_enclave_id_t global_eid, bool secure) 
{
    Timer t("no_processing");
    server_error_t ret = OK;

    // Thread open dedicated database connection 
    sqlite3 *db;

    if(DEBUG) printf("\nOpening dabase\n"); 

    if(sqlite3_open(DATABASE_PATH, &db)) {
       printf("SQL error: %s\n", sqlite3_errmsg(db));
       return print_error_message(OPEN_DATABASE_ERROR);
    } 

    uint8_t* processed_data = (uint8_t*)malloc(RESULT_MAX_SIZE);
    uint32_t real_size;

    if(secure == false) {
        ret = no_processing_i(rcv_msg, processed_data, &real_size);
        free(processed_data);
        if(!ret) database_write(db,rcv_msg); 
    }
    else {
        ret = no_processing_s(rcv_msg, global_eid, processed_data, &real_size);
        free(processed_data);
        if(!ret) database_write(db,rcv_msg);
    }

    sqlite3_close(db);
    return ret;
}

server_error_t aggregation_s(sqlite3* db, iot_message_t rcv_msg, uint8_t* processed_data, sgx_enclave_id_t global_eid, uint32_t* p_real_size) 
{ 
    Timer t("aggregation_s");
    server_error_t ret = OK;

    // Search user file and read sealed key
    char* publisher_seal_path = (char*)malloc(PATH_MAX_SIZE);
    sprintf(publisher_seal_path, "%s/%s", SEALS_PATH, rcv_msg.pk);

    if(DEBUG) printf("\nReading publisher key file: %s\n", publisher_seal_path);

    FILE* publisher_seal_file = fopen(publisher_seal_path, "rb");
    free(publisher_seal_path);
    if (publisher_seal_file == NULL) 
        return print_error_message(OPEN_CLIENT_KEY_FILE_ERROR);
    
    size_t publisher_sealed_size = sizeof(sgx_sealed_data_t) + sizeof(uint8_t)*16;
    uint8_t* publisher_sealed_data = (uint8_t*)malloc(publisher_sealed_size);
    fread(publisher_sealed_data,1,publisher_sealed_size,publisher_seal_file);
    fclose(publisher_seal_file);

    // Search server file and read sealed key
    char* storage_seal_path = (char*)malloc(PATH_MAX_SIZE);
    sprintf(storage_seal_path, "%s/storage_key", SEALS_PATH);

    if(DEBUG) printf("\nReading storage key file: %s\n", storage_seal_path);

    FILE* storage_seal_file = fopen(storage_seal_path, "rb");
    free(storage_seal_path);
    if (storage_seal_file == NULL) {
        free(publisher_sealed_data);     
        return print_error_message(OPEN_SERVER_KEY_FILE_ERROR);
    }

    size_t storage_sealed_size = sizeof(sgx_sealed_data_t) + sizeof(uint8_t)*16;
    uint8_t* storage_sealed_data = (uint8_t*)malloc(storage_sealed_size);
    fread(storage_sealed_data,1,storage_sealed_size,storage_seal_file);
    fclose(storage_seal_file);

    // Get DB request
    char* db_command = (char*)malloc(MAX_DB_COMMAND_SIZE);

    sgx_status_t sgx_status;
    sgx_status_t ecall_status;
    {
    Timer t2("get_db_request_s");

    if(DEBUG) printf("\nEntering enclave for decrypting publication message\n");

    sgx_status = get_db_request_s(global_eid, &ecall_status, 
                        rcv_msg.encrypted, 
                        rcv_msg.encrypted_size,
                        rcv_msg.pk, 
                        MAX_DB_COMMAND_SIZE,
                        (sgx_sealed_data_t*)publisher_seal_file, 
                        db_command);
    
    if(DEBUG) printf("Exiting enclave\n");

    if(sgx_status != SGX_SUCCESS || ecall_status != SGX_SUCCESS) {
        if(sgx_status == 0x5001) printf("Insuficient result buffer size.");
        else if(sgx_status == 0x5003) printf("\n(ins) Invalid plaintext client data format.\n");
        else printf("SGX error codes 0x%04x, 0x%04x\n", (int)sgx_status, (int)ecall_status);

        free(publisher_sealed_data);
        free(storage_sealed_data);
        free(db_command);
        return print_error_message(GET_DB_STATEMENT_ENCLAVE_ERROR);
    }
    }

    // Create arrays for datas and datas sizes 
    char** datas = (char**)malloc(MAX_NUM_DATAS_QUERIED*sizeof(char*)); 
    uint32_t* datas_sizes = (uint32_t*)malloc(MAX_NUM_DATAS_QUERIED*sizeof(uint32_t)); 
    uint32_t filtered_data_count = 0;

    // Coleect data for aggregation
    ret = database_read(db, db_command, datas, datas_sizes, &filtered_data_count);
    free(db_command);
    if(ret) {
        free(publisher_sealed_data);
        free(storage_sealed_data);
        free_data_array(datas, datas_sizes, filtered_data_count);
        return ret;
    }

    // Call function to aggregate 
    // pk|72d41281|type|weg_multimeter|payload|250110090|permission1|72d41281
    {
    Timer t3("sum_encrypted_data_s");

    if(DEBUG) printf("\nEntering enclave fo aggregating data\n");
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

    free(publisher_sealed_data);
    free(storage_sealed_data);
    free_data_array((char**)datas, datas_sizes, filtered_data_count);

    if(sgx_status != SGX_SUCCESS || ecall_status != SGX_SUCCESS) {
        if(sgx_status == 0x5001) printf("Insuficient result buffer size.");
        else if(sgx_status == 0x5003) printf("\n(ins) Invalid plaintext client data format.\n");
        else printf("SGX error codes 0x%04x, 0x%04x\n", (int)sgx_status, (int)ecall_status);
        return print_error_message(SUM_ENCRYPTED_ENCLAVE_ERROR);
    }
    }
    
    return OK;
}

server_error_t aggregation_i(sqlite3* db, iot_message_t rcv_msg, uint8_t* processed_data, uint32_t* p_real_size) {

    Timer t("aggregation_i");
    server_error_t ret = OK;

    // Search user file and read key
    char* publihser_key_path = (char*)malloc(PATH_MAX_SIZE);
    sprintf(publihser_key_path, "%s/%s_i", SEALS_PATH, rcv_msg.pk);

    if(DEBUG) printf("\nReading publisher key file: %s\n", publihser_key_path);

    FILE* publisher_key_file = fopen(publihser_key_path, "rb");
    free(publihser_key_path);
    if (publisher_key_file == NULL) 
        return print_error_message(OPEN_CLIENT_KEY_FILE_ERROR);

    size_t publisher_key_size = 16;
    uint8_t* publisher_key = (uint8_t*)malloc(publisher_key_size);
    fread(publisher_key,1,publisher_key_size,publisher_key_file);
    fclose(publisher_key_file);

    // Search server file and read storage key
    char* storage_key_path = (char*)malloc(PATH_MAX_SIZE);
    sprintf(storage_key_path, "%s/storage_key_i", SEALS_PATH);

    if(DEBUG) printf("\nReading storage key file: %s\n", storage_key_path);

    FILE* storage_key_file = fopen(storage_key_path, "rb");
    free(storage_key_path);
    if (storage_key_file == NULL) {
        free(publisher_key);
        return print_error_message(OPEN_SERVER_KEY_FILE_ERROR);
    }

    size_t storage_key_size = 16;
    uint8_t* storage_key = (uint8_t*)malloc(storage_key_size);
    fread(storage_key,1,storage_key_size,storage_key_file);
    fclose(storage_key_file);
    
    // Get DB request
    char* db_command = (char*)malloc(MAX_DB_COMMAND_SIZE);

    if((ret = get_db_request_i(rcv_msg, publisher_key, db_command))){
        free(publisher_key);
        free(storage_key);
        free(db_command);
        return ret;
    }

    // Create arrays for datas and datas sizes 
    char** datas = (char**)malloc(MAX_NUM_DATAS_QUERIED*sizeof(char*)); 
    uint32_t* datas_sizes = (uint32_t*)malloc(MAX_NUM_DATAS_QUERIED*sizeof(uint32_t)); 
    uint32_t filtered_data_count = 0;

    // Coleect data for aggregation
    ret = database_read(db, db_command, datas, datas_sizes, &filtered_data_count);
    free(db_command);
    if(ret) {
        free(publisher_key);
        free(storage_key);
        free_data_array(datas, datas_sizes, filtered_data_count);
        return ret;
    }

    // Call function to aggregate 
    // pk|72d41281|type|123456|payload|250110090|permission1|72d41281
    ret = sum_encrypted_data_i(rcv_msg.encrypted,
                            rcv_msg.encrypted_size,
                            publisher_key,
                            storage_key, 
                            (uint8_t**)datas, 
                            filtered_data_count, 
                            rcv_msg.pk, 
                            processed_data, 
                            p_real_size);
    free_data_array(datas, datas_sizes, filtered_data_count);
    free(publisher_key);
    free(storage_key);

    return print_error_message(ret);
}

server_error_t aggregation(iot_message_t rcv_msg, sgx_enclave_id_t global_eid, bool secure)
{
    Timer t("aggregation");
    server_error_t ret = OK;

    // Thread open dedicated database connection 
    sqlite3 *db;

    if(DEBUG) printf("\nOpening database\n"); 

    if(sqlite3_open(DATABASE_PATH, &db)) {
        printf("SQL error: %s\n", sqlite3_errmsg(db));
        return print_error_message(OPEN_DATABASE_ERROR);
    } 

    uint8_t* processed_data = (uint8_t*)malloc(RESULT_MAX_SIZE);
    uint32_t real_size;
    if(secure == false) 
        ret = aggregation_i(db, rcv_msg, processed_data, &real_size);
    else 
        ret = aggregation_s(db, rcv_msg, processed_data, global_eid, &real_size);

    if(!ret) {

        // Write data in file
        iot_message_t data_for_writing;
        memcpy(data_for_writing.pk, rcv_msg.pk, 9);
        sprintf(data_for_writing.type, "555555");
        data_for_writing.encrypted_size = real_size;    
        data_for_writing.encrypted = (uint8_t*)malloc(real_size);
        memcpy(data_for_writing.encrypted, processed_data, real_size);

        ret = database_write(db, data_for_writing);
        free(data_for_writing.encrypted);
    }

    free(processed_data);
    sqlite3_close(db);
    return ret;
}
