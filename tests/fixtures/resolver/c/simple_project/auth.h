#ifndef AUTH_H
#define AUTH_H

#include "db.h"

struct User {
    char name[64];
    int id;
};

struct User create_user(const char *name);

#endif
