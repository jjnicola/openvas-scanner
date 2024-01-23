use redis_storage::{CacheDispatcher, FEEDUPDATE_SELECTOR};
use storage::Storage;

use storage::item::ItemDispatcher;
use storage::{Retriever, ListRetriever, Retrieve};

fn main() {

    let redis= "unix:///run/redis-openvas/redis.sock";

    let cache = CacheDispatcher::init(redis, FEEDUPDATE_SELECTOR).unwrap();
    
    let oids = cache.retrieve_keys(&"nvt:*".to_string()).unwrap();

    for oid in oids.iter() {
        let metadata = cache.retrieve_nvt(oid).unwrap();

        println!("{:?}", metadata);
    }
    


}
