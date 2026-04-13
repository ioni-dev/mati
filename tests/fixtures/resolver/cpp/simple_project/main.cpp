#include "auth.hpp"
#include "db.hpp"

int main() {
    Auth::User u = Auth::createUser("admin");
    Db::Client c = Db::connect("localhost");
    return 0;
}
