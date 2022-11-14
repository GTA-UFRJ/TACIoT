/*
 * Teleinformatic and Automation Group (GTA, Coppe, UFRJ)
 * Author: Guilherme Araujo Thomaz
 * Descripton: auxiliary funtions and types
 * 
 * This code was modified following access permissions defined
 * by Intel Corporation license, presented as follows
 * 
 */

#include "utils.h"
#include <stdlib.h>
#include <string.h>
#include <chrono>
#include "sample_libcrypto.h"
#include "config_macros.h"

errno_t memcpy_s(
    void *dest,
    size_t numberOfElements,
    const void *src,
    size_t count)
{
    if(numberOfElements<count)
        return -1;
    memcpy(dest, src, count);
    return 0;
}

void PRINT_BYTE_ARRAY(
    FILE *file, void *mem, uint32_t len)
{
    if(!mem || !len)
    {
        fprintf(file, "\n( null )\n");
        return;
    }
    uint8_t *array = (uint8_t *)mem;
    fprintf(file, "%u bytes:\n{\n", len);
    uint32_t i = 0;
    for(i = 0; i < len - 1; i++)
    {
        fprintf(file, "0x%x, ", array[i]);
        if(i % 8 == 7) fprintf(file, "\n");
    }
    fprintf(file, "0x%x ", array[i]);
    fprintf(file, "\n}\n");
}

//uint8_t iv[12];

void gen_iv(uint8_t* iv)
{
    srand((unsigned)time(NULL));
    for(int i=0;i<12;i++)
    {
        //iv[i] = static_cast<uint8_t>(rand()%10) + 48;
        iv[i] = 0;
    }
}

void debug_print_encrypted(
    size_t encMessageLen, 
    uint8_t* encMessage){
        printf("Size = %d\nData = ", (int)encMessageLen);
        for (size_t byte=0; byte<encMessageLen; byte++){
            printf("0x%02x, ", encMessage[byte]);
        }
        printf("\n");
}



void free_data_array(char** datas, uint32_t* datas_sizes, uint32_t data_count) {
    for(unsigned i = 0; i < data_count; i++)
        free(datas[i]);
    free(datas);
    free(datas_sizes);
}