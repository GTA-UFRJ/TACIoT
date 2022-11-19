#include <stdio.h>
#include "server_database_manager.h"
#include <string.h>
#include "config_macros.h"
#include "utils.h"

// COMPILATION: g++ -c server/server_app/server_database_manager.cpp -o server/server_app/server_database_manager.o
// LINKEDITON: g++ server/server_app/server_database_manager.o -l sqlite3 -o server/server_app/server_database_manager

void free_callback_arg(callback_arg_t callback_arg) {
    for(unsigned i = 0; i < callback_arg.data_count; i++)
        free(callback_arg.datas[i]);
    free(callback_arg.datas);
    free(callback_arg.datas_sizes);
}

/*
 * received_from_exec = data passed througth the 4th argument of sqlite3_exec
 * num_columns = number of columns (fields) in the database
 * columns_values = array of strings with fields values for the corresponding row
 * columns_names = array of strings with columns names
 */
static int callback_query(void* received_from_exec, int num_columns, char** columns_values, char ** columns_names) {
    
    callback_arg_t* received_from_exec_tranformed = (callback_arg_t*)received_from_exec;

    // database_read only allocated the array. Now we will allocate memory for the string at the selected position
    char* new_data = (char*)malloc(MAX_DATA_SIZE*sizeof(char)); 

    // Navigate througth all colums of the queried entry
    for(int column_index = 0; column_index < num_columns; column_index++) {

        // Verify if column value is not NULL
        if(columns_values[column_index] == 0) {
            printf("Encountered NULL value at column %s\n", columns_names[column_index]);
            return -1;
        }
    }

    // Pick data encrypted size
    char* invalid_character;
    uint32_t encrypted_size = (uint32_t) strtoul(columns_values[2], &invalid_character, 10);

    if(*invalid_character != 0) {
        printf("Invalid character in size field: %c\n", *invalid_character);
        return -1;
    }
    
    // Build the data string
    sprintf(new_data, "type|%s|pk|%s|size|0x%02x|encrypted|", 
            columns_values[0], columns_values[1], encrypted_size);

    // Convert encrypted string into sequence of bytes
    char auxiliar[3];
    for (uint32_t byte_index = 0; byte_index < encrypted_size; byte_index++){
        auxiliar[0] = columns_values[3][3*byte_index];
        auxiliar[1] = columns_values[3][3*byte_index+1];
        auxiliar[2] = '\0';
        
        new_data[44+byte_index] = (char)strtoul(auxiliar, &invalid_character, 16);
        if(*invalid_character != 0) {
            printf("Invalid character in encrypted field: %c\n", *invalid_character);
            return -1;
        }
    }

    // Updtae structure for next callback call
    received_from_exec_tranformed->datas[received_from_exec_tranformed->data_count] = new_data;
    received_from_exec_tranformed->datas_sizes[received_from_exec_tranformed->data_count] = 44+encrypted_size;
    received_from_exec_tranformed->data_count++;
    
    return 0;
}

int database_write(sqlite3* db, iot_message_t rcv_msg) {
    
    if(DEBUG) printf("Writing to dabase\n"); 

    // Format encrypted message for publication
    char auxiliar[4];
    char *enc_write = (char*)malloc(3*rcv_msg.encrypted_size+1);
    for (int i=0; i<int(rcv_msg.encrypted_size); i++) {
        sprintf(auxiliar, "%02x-", rcv_msg.encrypted[i]);
        memcpy(&enc_write[3*i], auxiliar, 3);
    }
    enc_write[3*rcv_msg.encrypted_size] = '\0';
    
    // Create SQL statement for inserting data into the database
    char* insert_sql_statement = (char*)malloc((MAX_DATA_SIZE+100)*sizeof(char));
    sprintf(insert_sql_statement, 
    "INSERT INTO TACIOT (TYPE,PK,SIZE,ENCRYPTED) "\
    "VALUES ('%s','%s',%u,'%s');",
    rcv_msg.type, rcv_msg.pk, rcv_msg.encrypted_size, enc_write);
    
    if(DEBUG) printf("SQL insert statement: %s\n", insert_sql_statement); 

    // Execute SQL statetment for inserting data (without callback function)
    char *error_message = 0;
    int ret = sqlite3_exec(db, insert_sql_statement, NULL, NULL, &error_message);
    
    if(ret != SQLITE_OK ){
        printf("SQL error: %s\n", error_message);

        // Error message is allocated inside sqlite3_exec call IF ther were an error
        sqlite3_free(error_message);
        
        sqlite3_close(db);
        return -1;
    }

    return 0;
}

int database_read(sqlite3* db, char* command, char** datas, uint32_t* datas_sizes, uint32_t* data_count) {
   
    if(DEBUG) printf("Reading from database\n");

    if(DEBUG) printf("SQL read statement: %s\n", command); 

    // Replace "_" in command by SPACE character
    for(unsigned i=0; i<strlen(command); i++) 
        command[i] = (command[i] == '_') ? ' ' : command[i];
    
    callback_arg_t passed_to_callback;

    // Allocate an array with 2048 strings for the returned datas
    passed_to_callback.datas = (char**)malloc(MAX_NUM_DATAS_QUERIED*sizeof(char*));
    passed_to_callback.datas_sizes = (uint32_t*)malloc(MAX_NUM_DATAS_QUERIED*sizeof(uint32_t));    // 2048 = MAX_NUM_DATAS_QUERIED
    passed_to_callback.data_count = 0;

    // Execute SQL statetment for quering data (with callback function)
    char *error_message = 0;
    int ret = sqlite3_exec(db, command, callback_query, (void*)(&passed_to_callback), &error_message);

    if(ret != SQLITE_OK ){
        printf("SQL error: %s\n", error_message);

        // Error message is allocated inside sqlite3_exec call IF ther were an error
        sqlite3_free(error_message);
        
        sqlite3_close(db);
        free_callback_arg(passed_to_callback);
        return -1;
    }

    // Copy datas returned from callback by reference (suposing that datas is allocated)
    *data_count = passed_to_callback.data_count;
    uint32_t data_size; 
    for(unsigned i=0; i<passed_to_callback.data_count; i++) {
        data_size = passed_to_callback.datas_sizes[i];
        datas_sizes[i] = data_size;
        datas[i] = (char*)malloc(data_size * sizeof(char));
        memcpy(datas[i], (passed_to_callback.datas)[i], data_size);
    }

    return 0;
}
/*
int main () {

    // Testing publication
    iot_message_t msg;
    sprintf(msg.type, "555555");
    sprintf(msg.pk, "72d41281");
    msg.encrypted_size = 10;
    msg.encrypted = (uint8_t*)malloc(msg.encrypted_size);
    uint8_t enc[10] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
    memcpy(msg.encrypted, enc, msg.encrypted_size);

    sqlite3 *db;
    int ret = sqlite3_open("./database/taciot.db", &db);
    if(ret) {
       printf("Can't open database: %s\n", sqlite3_errmsg(db));
       return -1;
    } else {
       printf("Opened database successfully\n");
    }

    database_write(db, msg);

    // Testign query
    char** datas = (char**)malloc(2048*sizeof(char*));
    uint32_t* datas_sizes = (uint32_t*)malloc(2048*sizeof(uint32_t));
    uint32_t data_count = 0;
    char command[64] = "SELECT * from TACIOT where type=\"555555\"";
    database_read(db, command, datas, datas_sizes, &data_count);

    printf("data_count = %u\n", data_count);
    printf("datas_sizes[0] = %u\n", datas_sizes[0]);
    printf("datas[0] = %s\n", datas[0]);
    debug_print_encrypted((size_t)datas_sizes[0]-44, (uint8_t*)(datas[0]+44));

    free_data_array(datas, datas_sizes, data_count);

    sqlite3_close(db);

    return 0;
}
*/