use user::User;

pub mod cgka;
pub mod sumac;
pub mod tmka;


pub mod user;

pub mod key_package;
pub mod errors;
pub(crate) mod crypto;
pub mod test_utils;


#[derive(Clone)]
pub enum Operation {
    Add(User),
    Remove(User),
    Update(User),
}




