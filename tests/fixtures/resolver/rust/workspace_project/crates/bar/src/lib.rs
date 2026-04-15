pub mod util;

use crate::util;
use foo::from_foo;

pub fn from_bar() {
    util::from_bar_util();
    from_foo();
}
