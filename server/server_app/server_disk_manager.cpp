/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Description: manages the r/w operations in the database and key vault
 */

#include "server_disk_manager.h"

void file_write (iot_message_t rcv_msg, uint8_t* processed_data, uint32_t real_size)
{
    Timer t("file_write");
    // Write header in disk copy
    // type|123456|size|0x35|encrypted|AES128(pk|72d41281|type|weg_multimeter|payload|250110090|permission1|72d41281)
    char publish_header[5+6+4+8+6+4+11+1];
    sprintf(publish_header, "type|%s|pk|%s|size|0x%02x|encrypted|", rcv_msg.type, rcv_msg.pk, rcv_msg.encrypted_size);
    char db_path[DB_PATH_SIZE];
    sprintf(db_path, "%s", DB_PATH);
    FILE* db_file = fopen(db_path, "ab");
    if (db_file != NULL) {
        fwrite(publish_header, 1, (size_t)5+6+4+8+6+4+11, db_file);
    }
    fclose(db_file);

    char auxiliar[7];
    char *enc_write = (char*)malloc(6*real_size);
    for (int i=0; i<int(real_size); i++)
    {
        sprintf(auxiliar, "0x%02x--", processed_data[i]);
        memcpy(&enc_write[6*i], auxiliar, 6);
    }

    // Write result in disk copy
    sprintf(db_path, "%s", DB_PATH);
    db_file = fopen(db_path, "ab");
    if (db_file != NULL) {
        fwrite(enc_write, 1, (size_t)6*real_size, db_file);
        char nl = '\n';
        fwrite(&nl, 1, sizeof(char), db_file);
    }
    fclose(db_file);
    free(enc_write);
}

stored_data_t get_stored_parameters(char* msg)
{
    Timer t("get_stored_parameters");
    // type|%s|pk|%s|size|0x%02x|encrypted|
    stored_data_t stored;
    uint32_t index;
    char* token = strtok_r(msg, "|", &msg);
    int i = 0;
    char auxiliar[3];
    while (token != NULL && i<6)
    {
        i++;
        token = strtok_r(NULL, "|", &msg);
        // Get type     
        if (i == 1)
        {
            memcpy(stored.type, token, 6);
            stored.type[6] = '\0';
        }
        // Get client key       
        if (i == 3)
        {
            memcpy(stored.pk, token, 8);
            stored.pk[8] = '\0';
        }
        // Get encrypted message size
        if (i == 5)
        {
            stored.encrypted_size = (uint32_t)strtoul(token,NULL,16);
            //printf("%u\n", stored.encrypted_size);
        }
    }

    // Get encrypted
    stored.encrypted = (uint8_t*)malloc((stored.encrypted_size+1) * sizeof(uint8_t));
    if (stored.encrypted == NULL)
        printf("Allocation error\n");
    memcpy(stored.encrypted, msg, stored.encrypted_size);
    stored.encrypted[stored.encrypted_size] = 0;
    //debug_print_encrypted((size_t)(stored.encrypted_size), stored.encrypted);

    return stored;
}

void file_read(uint32_t index, char* data)
{
    Timer t("file_read");
    char db_path[DB_PATH_SIZE];
    sprintf(db_path, "%s", DB_PATH);
    FILE* db_file = fopen(db_path, "rb");
    if (db_file == NULL)
    {
        printf("Failed opening %s file", db_path);
    }
    fseek(db_file, (long)index, 0);
    char published_header[45];
    fread(published_header,1,44,db_file);
    published_header[44] = 0;
    memcpy(&data[0], published_header, 44);

    //printf("%s\n", published_header);

    char auxiliar[3];
    auxiliar[0] = published_header[31];
    auxiliar[1] = published_header[32];
    auxiliar[2] = '\0';
    uint32_t encrypted_size = (uint32_t)strtoul(auxiliar, NULL, 16);

    char *encrypted = (char*)malloc(6*encrypted_size+1);
    fread(encrypted,1,encrypted_size*6,db_file);
    for (uint32_t i=0; i<encrypted_size; i++){
        auxiliar[0] = encrypted[6*i+2];
        auxiliar[1] = encrypted[6*i+3];
        auxiliar[2] = '\0';
        data[44+i] = (char)strtoul(auxiliar, NULL, 16);
    }
    data[44+encrypted_size] = '\0';
    fclose(db_file);
    free(encrypted);
/*
    uint8_t* data_int = (uint8_t*)malloc(44+encrypted_size);
    memcpy(data_int, data, (size_t)(44+encrypted_size));
    debug_print_encrypted(44+(size_t)encrypted_size,data_int);
    free(data_int);
    */
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