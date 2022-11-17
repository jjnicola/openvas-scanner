use redis::*;

use std::fmt;

pub type Result<T> = std::result::Result<T, DbError>;

#[derive(Debug)]
pub enum DbError {
    RedisErr {source: String, detail: String},
    CustomErr(String),
}

impl fmt::Display for DbError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &*self {
            DbError::RedisErr {source, detail} => write!(f, "Redis Error: {source}. {detail}"),
            DbError::CustomErr(e) => write!(f, "Error: {}", e),
        }
    }
}

impl From<RedisError> for DbError {
    fn from(err: RedisError) -> DbError {
        let mut detail = "";
        if let Some(d) = err.detail() {
            detail = d;
        }
        DbError::RedisErr {source: err.to_string(), detail: detail.to_string()}
    }
}
