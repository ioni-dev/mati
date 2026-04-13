#include "auth.h"
#include "db.h"

int main(void) {
    struct User u = create_user("admin");
    struct DbClient c = db_connect("localhost");
    return 0;
}
