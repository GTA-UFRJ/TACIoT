#include <stdlib.h>
#include <sqlite3.h>
#include <string>

// Just for tests
typedef struct iot_message_t
{
    char pk[9];
    char type[7];
    uint32_t encrypted_size;
    uint8_t* encrypted;
} iot_message_t;

typedef struct callback_arg_t
{
    char** datas;
    uint32_t* datas_sizes;
    uint32_t data_count;
} callback_arg_t;

void debug_print_encrypted(size_t, uint8_t*);

void free_data_array(char**, uint32_t*, uint32_t);

void free_callback_arg(callback_arg_t );

static int callback_query(void*, int, char**, char **);

int database_write(sqlite3*, iot_message_t);

int database_read(sqlite3*, char*, char**, uint32_t*, uint32_t*);
