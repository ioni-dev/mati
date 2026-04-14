#ifndef AUTH_HPP
#define AUTH_HPP

#include "db.hpp"

namespace Auth {

struct User {
    char name[64];
    int id;
};

User createUser(const char *name);

}

#endif
