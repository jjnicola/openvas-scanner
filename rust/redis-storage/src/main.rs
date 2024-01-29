
use redis_storage::{CacheDispatcher, VtHelper, FEEDUPDATE_SELECTOR, NOTUSUPDATE_SELECTOR};
use storage::Storage;

use storage::item::ItemDispatcher;
use storage::{Retriever, ListRetriever, Retrieve};

fn main() {

    let redis= "unix:///run/redis-openvas/redis.sock";


    let c = redis_storage::CacheDispatcher::as_dispatcher(redis, FEEDUPDATE_SELECTOR);

    
    //let notus_cache = CacheDispatcher::init(redis, NOTUSUPDATE_SELECTOR).unwrap();

    
    //let vts_cache = CacheDispatcher::init(redis, FEEDUPDATE_SELECTOR).unwrap();

  //  let cache = VtHelper::new(notus_cache, vts_cache);
    
    //let oids = cache.retrieve_vts(None, false).unwrap();


    //for oid in oids.iter() {
    //    let metadata = cache.retrieve_vt(oid).unwrap();
    //    let json_str = serde_json::to_string(&metadata).unwrap();
    //    println!("{json_str}");
    //    
    //}

}

