/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Descripton: configuration flags
 */

#ifndef DEBUG_PRINT 
#define DEBUG_PRINT 1
#endif

#ifndef TOKENS_PATH
#define TOKENS_PATH "/home/guiaraujo/TACIoT/server/tokens"
#endif

#ifndef PATH_MAX_SIZE 
#define PATH_MAX_SIZE 128
#endif

#ifndef ENCLAVE_PATH
#define ENCLAVE_PATH "server_enclave.signed.so"
#endif

#ifndef URL_MAX_SIZE
#define URL_MAX_SIZE 4096
#endif

#ifndef TEST_CLIENT_URL
#define TEST_CLIENT_URL "localhost"
#endif

#ifndef SERVER_URL
#define SERVER_URL "0.0.0.0"
#endif

#ifndef SERVER_PORT
#define SERVER_PORT 5555
#endif

#ifndef HTTPLIB_PATH
#define HTTPLIB_PATH "/home/guiaraujo/cpp-httplib/httplib.h"
#endif

#ifndef SEALS_PATH
#define SEALS_PATH "/home/guiaraujo/TACIoT/server/seals"
#endif

#ifndef LATENCY_MS
#define LATENCY_MS 0
#endif

#ifndef CLIENT_GXGYPK
#define CLIENT_GXGYPK "72128a7a17526ebf85d03a623730aead3e3daaee9c60731db05be8621c4beb38d48140d950e2577b26eeb741e7c614e224b7bdc903f29a28a83cc81011145e06"
#endif

#ifndef CLIENT_ID
#define CLIENT_ID "72d41281"
#endif

#ifndef DATA_TYPE_SAMPLE
#define DATA_TYPE_SAMPLE "123456"
#endif

#ifndef DATA_TYPE_SIZE
#define DATA_TYPE_SIZE 6
#endif

#ifndef ULTRALIGHT_SAMPLE
#define ULTRALIGHT_SAMPLE "pk|72d41281|type|123456|payload|250|permission1|72d41281"
#endif

#ifndef ULTRALIGHT_SIZE
#define ULTRALIGHT_SIZE 56
#endif

#ifndef SHARED_SECRET
#define SHARED_SECRET "00000000000000000000000000000000"
#endif

#ifndef SEALED_SIZE
#define SEALED_SIZE 8192
#endif

#ifndef RESULT_MAX_SIZE
#define RESULT_MAX_SIZE 1024
#endif

#ifndef MAX_DATA_SIZE
#define MAX_DATA_SIZE 1024
#endif

#ifndef DB_PATH
#define DB_PATH "/home/guiaraujo/TACIoT/database/sample"
#endif

#ifndef DB_PATH_SIZE
#define DB_PATH_SIZE 39
#endif

#ifndef TOKEN_NAME
#define TOKEN_NAME "72d41281"
#endif

#ifndef MAX_ENC_DATA_SIZE
#define MAX_ENC_DATA_SIZE 1024
#endif

#ifndef MAX_AGGREGATION_TOTAL_SIZE
#define MAX_AGGREGATION_TOTAL_SIZE 20
#endif

#ifndef PK_SAMPLE
#define PK_SAMPLE "72d41281"
#endif

#ifndef GENERIC_MEASURE_PAYLOAD_SAMPLE
#define GENERIC_MEASURE_PAYLOAD_SAMPLE "250"
#endif

#ifndef GENERIC_MEASURE_PAYLOAD_SIZE_SAMPLE
#define GENERIC_MEASURE_PAYLOAD_SIZE_SAMPLE 3
#endif

#ifndef GENERIC_MEASURE_TYPE_SAMPLE
#define GENERIC_MEASURE_TYPE_SAMPLE "123456"
#endif

#ifndef AGGREGATE_GMT_TYPE_SAMPLE
#define AGGREGATE_GMT_TYPE_SAMPLE "555555"
#endif

#ifndef GENERIC_MEASURE_PERMISSION_1_SAMPLE
#define GENERIC_MEASURE_PERMISSION_1_SAMPLE "72d41281"
#endif

#ifndef AGGREGATE_GMT_PERMISSION_1_SAMPLE
#define AGGREGATE_GMT_PERMISSION_1_SAMPLE "72d41281"
#endif

#ifndef MAX_NUM_DATAS_QUERIED
#define MAX_NUM_DATAS_QUERIED 2048
#endif

#ifndef MAX_DB_COMMAND_SIZE
#define MAX_DB_COMMAND_SIZE 2048
#endif

#ifndef DATABASE_PATH
#define DATABASE_PATH "/home/guiaraujo/TACIoT/database/taciot.db"
#endif

#ifndef MAX_PAYLOAD_SIZE
#define MAX_PAYLOAD_SIZE 128
#endif

#ifndef DEFAULT_PERMS_DB_PATH
#define DEFAULT_PERMS_DB_PATH "/home/guiaraujo/TACIoT/database/default_permissions.db"
#endif

#ifndef MAX_NUM_PERMISSIONS
#define MAX_NUM_PERMISSIONS 16
#endif

#ifndef CLIENT_KEY_FILENAME
#define CLIENT_KEY_FILENAME "/home/guiaraujo/TACIoT/database/identity"
#endif

#ifndef AP_URL
#define AP_URL "localhost"
#endif

#ifndef AP_PORT
#define AP_PORT 8080
#endif

#ifndef MAX_ARG_SIZE
#define MAX_ARG_SIZE 256
#endif

#ifndef MAX_NUM_ARGS
#define MAX_NUM_ARGS 16
#endif