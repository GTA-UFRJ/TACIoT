/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Description: manages the r/w operations in the database and key vault
 */

#include "server_disk_manager.h"
#include <mutex>
#include <unistd.h>
 
std::mutex thread_sync;

int file_write (iot_message_t rcv_msg, uint8_t* processed_data, uint32_t real_size)
{
    Timer t("file_write");

    // Avoid multiple threads writing at the same time
    thread_sync.lock();

    // Write header in disk copy
    // type|123456|pk|72d41281|size|0x54|encrypted|
    char publish_header[5+6+4+8+6+4+11+1];
    sprintf(publish_header, "type|%s|pk|%s|size|0x%02x|encrypted|", rcv_msg.type, rcv_msg.pk, rcv_msg.encrypted_size);

    char db_path[DB_PATH_SIZE];
    sprintf(db_path, "%s", DB_PATH);

    FILE* db_file = fopen(db_path, "ab");
    if (db_file != NULL) {
        fwrite(publish_header, 1, (size_t)5+6+4+8+6+4+11, db_file);
    }
    fclose(db_file);

    char auxiliar[4];
    char *enc_write = (char*)malloc(3*real_size+2);
    for (int i=0; i<int(real_size); i++) {
        sprintf(auxiliar, "%02x-", processed_data[i]);
        memcpy(&enc_write[3*i], auxiliar, 3);
    }
    enc_write[3*real_size] = '\n';
    enc_write[3*real_size+1] = '\0';

    if(DEBUG) printf("\nWriting data to file: %s%s\n", publish_header, enc_write);

    // Write result in disk copy
    sprintf(db_path, "%s", DB_PATH);
    db_file = fopen(db_path, "ab");
    if (db_file != NULL) {
        fwrite(enc_write, 1, (size_t)3*real_size+1, db_file);
    }
    fclose(db_file);
    free(enc_write);

    // Next thread gets the lock ate the start of the function
    thread_sync.unlock();

    return 0;
}

int get_stored_parameters(char* msg, stored_data_t* p_stored)
{
    Timer t("get_stored_parameters");

    if(DEBUG) printf("\nParsing stored data fields\n");

    // type|123456|pk|72d41281|size|0x54|encrypted|0x62-
    char* token = strtok_r(msg, "|", &msg);
    int i = 0;
    char auxiliar[3];
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

    return 0;
}

int file_read(uint32_t index, char* data)
{
    Timer t("file_read");

    char db_path[DB_PATH_SIZE];
    sprintf(db_path, "%s", DB_PATH);

    FILE* db_file = fopen(db_path, "rb");
    if (db_file == NULL) {
        printf("Failed opening %s file", db_path);
        return -1;
    }

    // Adjust cursor
    fseek(db_file, (long)index, 0);
    
    char published_header[45];
    fread(published_header,1,44,db_file);
    published_header[44] = 0;
    memcpy(data, published_header, 44);

    //printf("%s\n", published_header);

    char auxiliar[3];
    auxiliar[0] = published_header[31];
    auxiliar[1] = published_header[32];
    auxiliar[2] = '\0';
    uint32_t encrypted_size = (uint32_t)strtoul(auxiliar, NULL, 16);

    char *encrypted = (char*)malloc(3*encrypted_size+1);
    fread(encrypted,1,encrypted_size*3,db_file);
    for (uint32_t i=0; i<encrypted_size; i++){
        auxiliar[0] = encrypted[3*i];
        auxiliar[1] = encrypted[3*i+1];
        auxiliar[2] = '\0';
        data[44+i] = (char)strtoul(auxiliar, NULL, 16);
    }
    data[44+encrypted_size] = '\0';
    fclose(db_file);
    free(encrypted);
    
    return 0;
}

uint32_t count_entries() {
    char db_path[DB_PATH_SIZE];
    sprintf(db_path, "%s", DB_PATH); 
    FILE* db_file = fopen(db_path, "rb");
    if (db_file == NULL)
    {
        printf("Failed opening %s file", db_path);
    }

    uint32_t count = 0;
    char c;
    for(c = getc(db_file); c != EOF; c = getc(db_file)) 
        if (c == '\n')
            count++;
    fclose(db_file);
    
    return count;   
}

bool verify_file_existance(char* filename) 
{
    Timer t("verify_file_existance");
    return ( access(filename, F_OK) != -1 ? true : false );
}

int write_key(char* pk, uint8_t* ck, uint32_t ck_size, char* filename) 
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