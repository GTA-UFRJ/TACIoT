/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Description: manages the r/w operations in the database and key vault
 */

#include "server_disk_manager.h"
#include <mutex>
#include <unistd.h>
#include "errors.h"
 
std::mutex thread_sync;

server_error_t get_stored_parameters(char* msg, stored_data_t* p_stored)
{
    Timer t("get_stored_parameters");

    if(DEBUG) printf("\nParsing stored data fields\n");

    // type|123456|pk|72d41281|size|0x54|encrypted|0x62-
    char* token = strtok_r(msg, "|", &msg);
    int i = 0;
    while (token != NULL && i<6)
    {
        i++;
        token = strtok_r(NULL, "|", &msg);

        // Get type     
        if (i == 1) {
            memcpy(p_stored->type, token, 6);
            p_stored->type[6] = '\0';

            if(DEBUG) printf("type: %s\n", p_stored->type);
        }

        // Get client key       
        if (i == 3) {
            memcpy(p_stored->pk, token, 8);
            p_stored->pk[8] = '\0';

            if(DEBUG) printf("pk: %s\n", p_stored->pk);
        }

        // Get encrypted message size
        if (i == 5) {
            p_stored->encrypted_size = (uint32_t)strtoul(token,NULL,16);
            if(DEBUG) printf("encrypted_size: %u\n", p_stored->encrypted_size);
        }
    }

    // Get encrypted
    p_stored->encrypted = (uint8_t*)malloc((p_stored->encrypted_size+1) * sizeof(uint8_t));
    
    memcpy(p_stored->encrypted, msg, p_stored->encrypted_size);
    p_stored->encrypted[p_stored->encrypted_size] = 0;
    //debug_print_encrypted((size_t)(stored.encrypted_size), stored.encrypted);

    return OK;
}

bool verify_file_existance(char* filename) 
{
    Timer t("verify_file_existance");
    return ( access(filename, F_OK) != -1 ? true : false );
}

int write_key(uint8_t* ck, uint32_t ck_size, char* filename) 
{
    Timer t("write_key");    

    // Avoid multiple threads writing at the same time
    thread_sync.lock();

    // Write key to file
    FILE* file = fopen(filename, "ab");
    if (file == NULL) {
        printf("\nFailed to open the key file %s\n", filename);
        fclose(file);
        return -1;
    }
    fwrite(ck, 1, (size_t)ck_size, file);
    fclose(file);

    // Next thread gets the lock ate the start of the function
    thread_sync.unlock();
    
    return 0;
}