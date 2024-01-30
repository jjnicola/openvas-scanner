// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::{marker::PhantomData, sync::Arc};

use async_trait::async_trait;
use futures_util::lock::Mutex;
use tokio::sync::RwLock;
use redis_storage::{CacheDispatcher, VtHelper, FEEDUPDATE_SELECTOR, NOTUSUPDATE_SELECTOR, dberror::RedisStorageResult, RedisCtx, RedisWrapper, RedisAddNvt, RedisAddAdvisory, RedisGetNvt};
use storage::StorageError;

#[async_trait]
pub trait GetVts {
    async fn get_vts(&self, vt_selection: Option<Vec<String>>) -> Vec<String>;
}


pub struct GetVtsWrapper<R,K>
where
    R: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt + Sync + Send,
    K: AsRef<str> + Sync + Send,
{
    vthelper: RwLock<VtHelper<R,K>>,
    phantom: PhantomData<R>
}

impl<R, K> GetVtsWrapper<R,K>
where
    R: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt + Sync + Send,
    K: AsRef<str> + Sync + Send,
{
    pub fn new(vthelper: VtHelper<R, K>) -> Self {

        
        Self {
            vthelper: RwLock::new(vthelper),
            phantom: PhantomData,
        }
    }
}

#[async_trait]
impl<R,K> GetVts for GetVtsWrapper<R,K>
where
    R: RedisWrapper + RedisAddNvt + RedisAddAdvisory + RedisGetNvt + Sync + Send, 
    K: AsRef<str> + Sync + Send,
{
   
    async fn get_vts(&self, vt_selection: Option<Vec<String>>) ->  Vec<String> {
        

        self.vthelper.read().await.get_oids().unwrap()
    }
}
