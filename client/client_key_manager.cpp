/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Description: configure key and ID
 */

#include "client_key_manager.h"
#include "errors.h"
#include <mutex>

std::mutex thread_sync;

// pk|72d41281|ck|00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-
int parse_configure_key_message(char* msg, client_identity_t* p_rcv_msg) {

    char* token = strtok_r(msg, "|", &msg);
    int i = 0;
    char auxiliar[3];
    while (token != NULL)
    {
        i++;
        token = strtok_r(NULL, "|", &msg);

        // Get client key
        if (i == 1){
            memcpy(p_rcv_msg->pk, token, 8);
            p_rcv_msg->pk[8] = '\0';
        }

        // Get communication key
        if (i == 3) {

            char* invalid_char;
            for (uint32_t j=0; j<16; j++){
                auxiliar[0] = token[3*j];
                auxiliar[1] = token[3*j+1];
                auxiliar[2] = '\0';
                p_rcv_msg->comunication_key[j] = (uint8_t)strtoul(auxiliar, &invalid_char, 16);

                if(auxiliar != 0 && *invalid_char != 0) {
                    printf("\nInvalid register message format.\n");
                    return (int)INVALID_REGISTRATION_KEY_FIELD_ERROR;
                }
            }
        }
    }

    return 0;
}

int get_configure_key_message(const httplib::Request& req, char* snd_msg, uint32_t* p_size)
{
    if(DEBUG) printf("\nGetting configure key message fields:\n");

    std::string size_field = req.matches[1].str();

    try {
        *p_size = (uint32_t)std::stoul(size_field);
    }
    catch (std::invalid_argument& exception) {
        return (int)print_error_message(INVALID_HTTP_MESSAGE_SIZE_FIELD_ERROR);
    }

    if(*p_size > URL_MAX_SIZE)
        return (int)print_error_message(HTTP_MESSAGE_SIZE_OVERFLOW_ERROR);

    if(DEBUG) printf("Size: %u\n", *p_size);

    std::string message_field = req.matches[2].str();

    strncpy(snd_msg, message_field.c_str(), (size_t)(*p_size-1));
    snd_msg[*p_size] = '\0';
    
    if(DEBUG) printf("Message: %s\n", snd_msg);

    return OK;
}

int read_identity(client_identity_t* p_id) {

    // Search identity file and read ID and CK
    if(DEBUG) printf("\nReading client identity key file: %s\n", CLIENT_KEY_FILENAME);

    FILE* id_file = fopen(CLIENT_KEY_FILENAME, "rb");
    if (id_file == NULL) 
        return (int)print_error_message(OPEN_CLIENT_KEY_FILE_ERROR);

    fread(p_id->pk, 1, 8, id_file);
    (p_id->pk)[8] = '\0';
    fread(p_id->comunication_key, 1, 16, id_file);
    
    fclose(id_file);
    return 0;
}

int write_identity(client_identity_t id) {

    // Avoid multiple threads writing at the same time
    thread_sync.lock();

    // Marshall structure

    // Write key to file
    FILE* file = fopen(CLIENT_KEY_FILENAME, "wb");
    if (file == NULL) {
        printf("\nFailed to open the key file %s\n", CLIENT_KEY_FILENAME);
        fclose(file);
        return -1;
    }
    fwrite(id.pk, 1, 8, file);
    fwrite(id.comunication_key, 1, 16, file);
    fclose(file);

    // Next thread gets the lock at the start of the function
    thread_sync.unlock();
    
    return 0;
}

int configure_device(client_identity_t rcv_id) {

    // Write identity into a file
    return write_identity(rcv_id);

    // Register client in the server (TODO)

}