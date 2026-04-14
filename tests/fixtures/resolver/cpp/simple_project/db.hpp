#ifndef DB_HPP
#define DB_HPP

namespace Db {

struct Client {
    char dsn[128];
};

Client connect(const char *dsn);

}

#endif
