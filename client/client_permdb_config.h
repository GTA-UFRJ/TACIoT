#include <stdlib.h>
#include <string> 
#include <sqlite3.h>

inline bool verify_if_file_exists (const std::string& );

static int callbacallback_create_tableck(void*, int, char**, char **);

int configure_database();