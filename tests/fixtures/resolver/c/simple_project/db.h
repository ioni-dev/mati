#ifndef DB_H
#define DB_H

struct DbClient {
    char dsn[128];
};

struct DbClient db_connect(const char *dsn);

#endif
