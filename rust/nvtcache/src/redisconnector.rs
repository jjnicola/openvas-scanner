use crate::dberror::DbError;
use crate::dberror::Result;
use crate::nvt::Nvt;
use redis::*;
use std::collections::LinkedList;

const GLOBAL_DBINDEX_NAME: &str = "GVM.__GlobalDBIndex";
const REDIS_DEFAULT_PATH: &str = "unix:///run/redis/redis-server.sock";

pub enum KbNvtPos {
    NvtFilenamePos,
    NvtRequiredKeysPos,
    NvtMandatoryKeysPos,
    NvtExcludedKeysPos,
    NvtRequiredUDPPortsPos,
    NvtRequiredPortsPos,
    NvtDependenciesPos,
    NvtTagsPos,
    NvtCvesPos,
    NvtBidsPos,
    NvtXrefsPos,
    NvtCategoryPos,
    NvtFamilyPos,
    NvtNamePos,
    //The last two members aren't stored.
    NvtTimestampPos,
    NvtOIDPos,
}

pub struct RedisCtx {
    kb: Connection, //a redis connection
    db: u32,        // the name space
    maxdb: u32,     // max db index
}

#[derive(Debug, PartialEq)]
pub struct RedisValueHandler {
    v: String,
}

impl FromRedisValue for RedisValueHandler {
    fn from_redis_value(v: &Value) -> RedisResult<RedisValueHandler> {
        match v {
            Value::Nil => Ok(RedisValueHandler { v: String::new() }),
            _ => {
                let new_var: String = from_redis_value(v).unwrap_or("".to_string());
                Ok(RedisValueHandler { v: new_var })
            }
        }
    }
}

impl RedisCtx {
    /// Connect to the redis server and return a redis context object
    pub fn new() -> Result<RedisCtx> {
        let client = redis::Client::open(REDIS_DEFAULT_PATH)?;
        let kb = client.get_connection()?;
        let mut redisctx = RedisCtx {
            kb,
            db: 0,
            maxdb: 0,
        };
        let _kbi = redisctx.select_database()?;
        Ok(redisctx)
    }

    /// Get the max db index configured for the redis server instance
    fn max_db_index(&mut self) -> Result<u32> {
        if self.maxdb > 0 {
            return Ok(self.maxdb);
        }

        let maxdb = Cmd::new()
            .arg("CONFIG")
            .arg("GET")
            .arg("databases")
            .query(&mut self.kb);

        match maxdb {
            Ok(mdb) => {
                let res: Vec<String> = mdb;
                self.maxdb = max_db_index_to_uint(res);
                return Ok(self.maxdb);
            }
            Err(_) => {
                return Err(DbError::CustomErr(String::from(
                    "Not possible to select a free database.",
                )))
            }
        }
        /// Redis always replies about config with a vector
        /// of 2 string ["databases", "Number"]
        /// Therefore we convert the "Number" to uint32
        fn max_db_index_to_uint(res: Vec<String>) -> u32 {
            if res.len() == 2 {
                match res[1].to_string().parse::<u32>() {
                    Ok(m) => return m,
                    Err(e) => {
                        println!("{}", e);
                        return 0 as u32;
                    }
                }
            }
            return 0 as u32;
        }
    }

    pub fn get_namespace(&mut self) -> Result<u32> {
        let db: u32 = self.db;
        Ok(db)
    }

    fn set_namespace(&mut self, db_index: u32) -> Result<String> {
        Cmd::new()
            .arg("SELECT")
            .arg(db_index.to_string())
            .query(&mut self.kb)?;

        self.db = db_index;
        return Ok(String::from("ok"));
    }

    fn try_database(&mut self, dbi: u32) -> Result<u32> {
        let ret = self.kb.hset_nx(GLOBAL_DBINDEX_NAME, dbi, 1)?;
        Ok(ret)
    }

    fn select_database(&mut self) -> Result<u32> {
        let maxdb: u32 = self.max_db_index()?;
        let mut selected_db: u32 = 0;

        // Start always from 1. Namespace 0 is reserved
        //format GLOBAL_DBINDEX_NAME
        for i in 1..maxdb {
            let ret = self.try_database(i)?;
            if ret == 1 {
                selected_db = i;
                break;
            }
        }
        if selected_db > 0 {
            self.set_namespace(selected_db)?;
            return Ok(self.db);
        }
        return Err(DbError::CustomErr(String::from(
            "Not possible to select a free db",
        )));
    }

    /// Delete an entry from the in-use namespace's list
    fn release_namespace(&mut self) -> Result<()> {
        // Get firstthe current db index, the one to be released
        let dbi = self.get_namespace()?;
        // Remove the entry from the hash list
        self.set_namespace(0)?;
        self.kb.hdel(GLOBAL_DBINDEX_NAME, dbi)?;
        Ok(())
    }

    /// Delete all keys in the namespace and relase the it
    pub fn delete_namespace(&mut self) -> Result<()> {
        Cmd::new().arg("FLUSHDB").query(&mut self.kb)?;
        self.release_namespace()?;
        Ok(())
    }
    //Wrapper function to avoid accessing kb member directly.
    pub fn redis_set_key<T: ToRedisArgs>(&mut self, key: &str, val: T) -> Result<()> {
        let _: () = self.kb.set(key, val)?;
        Ok(())
    }

    pub fn redis_add_item<T: ToRedisArgs>(&mut self, key: String, val: T) -> Result<String> {
        let ret: RedisValueHandler = self.kb.lpush(key, val)?;
        Ok(ret.v)
    }

    pub fn redis_get_key(&mut self, key: &str) -> Result<String> {
        let ret: RedisValueHandler = self.kb.get(key)?;
        Ok(ret.v)
    }

    pub fn redis_get_item(&mut self, key: String, index: KbNvtPos) -> Result<String> {
        let ret: RedisValueHandler = self.kb.lindex(key, index as isize)?;
        Ok(ret.v)
    }

    pub fn redis_del_key(&mut self, key: String) -> Result<String> {
        let ret: RedisValueHandler = self.kb.del(key)?;
        Ok(ret.v)
    }

    pub fn redis_add_nvt(&mut self, mut nvt: Nvt, filename: String) -> Result<()> {
        let oid = nvt.get_oid()?;
        let name = nvt.get_name()?;
        let required_keys = nvt.get_required_keys()?;
        let mandatory_keys = nvt.get_mandatory_keys()?;
        let excluded_keys = nvt.get_excluded_keys()?;
        let required_udp_ports = nvt.get_required_udp_ports()?;
        let required_ports = nvt.get_required_ports()?;
        let dependencies = nvt.get_dependencies()?;
        let tags = nvt.get_tag()?;
        // TODO: add functions to get the refs
        let xrefs = String::new();
        let bids = String::new();
        let cves = String::new();
        //---------------------------------------
        let category = nvt.get_category()?;
        let family = nvt.get_family()?;

        let mut key_name: String = "nvt:".to_owned();
        key_name = key_name + oid.as_ref();
        Cmd::new()
            .arg("RPUSH")
            .arg(key_name)
            .arg(filename)
            .arg(required_keys)
            .arg(mandatory_keys)
            .arg(excluded_keys)
            .arg(required_udp_ports)
            .arg(required_ports)
            .arg(dependencies)
            .arg(tags)
            .arg(cves)
            .arg(bids)
            .arg(xrefs)
            .arg(category)
            .arg(family)
            .arg(name)
            .query(&mut self.kb)?;

        //TODO: Add preferences

        nvt.destroy();

        return Ok(());
    }
}
