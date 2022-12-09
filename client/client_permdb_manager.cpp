/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Description: manages the r/w operations concerning deafult access permissions
 */

#include <stdio.h>
#include "client_permdb_manager.h"
#include <string.h>
#include "config_macros.h"
#include "errors.h"

void free_callback_arg(callback_arg_t callback_arg) {
    for(unsigned i = 0; i < callback_arg.data_count; i++)
        free(callback_arg.datas[i]);
    free(callback_arg.datas);
}

/*
 * received_from_exec = data passed througth the 4th argument of sqlite3_exec
 * num_columns = number of columns (fields) in the database
 * columns_values = array of strings with fields values for the corresponding row
 * columns_names = array of strings with columns names
 */
static int callback_perms(void* received_from_exec, int , char** columns_values, char ** ) {
    
    callback_arg_t* received_from_exec_tranformed = (callback_arg_t*)received_from_exec;

    // Verify if access permissions column value is not NULL
    if(columns_values[1] == 0) {
        printf("NULL access permission for the data type\n");
        return -1;
    }

    // Verify if number of access permissions is greater than the maximum
    uint32_t number_access_permissions = (uint32_t)strlen(columns_values[1]) / 9;
    if(number_access_permissions > MAX_NUM_PERMISSIONS) {
        printf("Number of access permissions greater than the maximum allowed\n");
        return -1;
    }
    received_from_exec_tranformed->data_count = number_access_permissions;

    // Fill array with access permissions
    for(uint32_t index=0; index<number_access_permissions; index++) {
        (received_from_exec_tranformed->datas)[index] = (char*)malloc(9);
        strncpy((received_from_exec_tranformed->datas)[index], columns_values[1], 8);
        (received_from_exec_tranformed->datas)[index][8] = '\0';
    }

    return 0;
}

int read_default_perms(sqlite3* db, char* type, char** permissions_list, uint32_t* permissions_count) {

    // Build SQL statement form quering data
    char* command = (char*)malloc(MAX_DB_COMMAND_SIZE);
    sprintf(command, "SELECT * from PERMS where type='%s'", type);

    // Allocate an array with 16 access permissions
    callback_arg_t passed_to_callback;
    passed_to_callback.datas = (char**)malloc(MAX_NUM_PERMISSIONS*sizeof(char*));

    // Execute SQL statement
    char *error_message = 0;
    int ret = sqlite3_exec(db, command, callback_perms, (void*)(&passed_to_callback), &error_message);
    free(command);

    if(ret != SQLITE_OK ){
        printf("SQL error: %s\n", error_message);

        // Error message is allocated inside sqlite3_exec call IF ther were an error
        sqlite3_free(error_message);
        
        sqlite3_close(db);
        free_callback_arg(passed_to_callback);

        return (int)print_error_message(DB_SELECT_EXECUTION_ERROR);
    }

    *permissions_count = passed_to_callback.data_count;
    for(unsigned i=0; i<passed_to_callback.data_count; i++) {
        permissions_list[i] = (char*)malloc(9);
        memcpy(permissions_list[i], (passed_to_callback.datas)[i], 9);
    }
    free_callback_arg(passed_to_callback);

    return 0;
}

int write_default_perms(sqlite3* db, char* type, char** permissions_list, uint32_t permissions_count) {

    // Build permissions string separted with ",""
    char* permissions = (char*)malloc((size_t)(9*permissions_count+1));
    for(uint32_t index=0; index<permissions_count; index++) {
        memcpy(permissions+9*index, permissions_list[index], 8);
        permissions[9*(index+1)-1] = ',';
    }
    permissions[9*permissions_count] = '\0';

    // Build SQL statement form writing data
    char* command = (char*)malloc(MAX_DB_COMMAND_SIZE);
    sprintf(command, 
    " INSERT INTO PERMS (TYPE, PERM_LIST)"\
    " VALUES ('%s','%s')", 
    type, permissions);
    free(permissions);

    // Execute SQL statement
    char *error_message = 0;
    int ret = sqlite3_exec(db, command, NULL, NULL, &error_message);
    free(command);

    if(ret != SQLITE_OK ){
        printf("SQL error: %s\n", error_message);

        // Error message is allocated inside sqlite3_exec call IF ther were an error
        sqlite3_free(error_message);
        
        sqlite3_close(db);

        return (int)print_error_message(DB_SELECT_EXECUTION_ERROR);
    }

    return 0;
}