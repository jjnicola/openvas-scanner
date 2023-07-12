// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::{error::Error};

use futures::{Stream};
use hyper::{body::Bytes};
use serde::Serialize;



type Result = hyper::Response<hyper::Body>;

#[derive(Debug, Default)]
pub struct Response {
    authentication: String,
    version: String,
}

impl Response {
    async fn create_stream<J, O, E>(&self, code: hyper::StatusCode, value: J) -> Result
    where
        J: Stream<Item = std::result::Result<O, E>> + Send + 'static,
        O: Into<Bytes> + 'static,
        E: Into<Box<dyn std::error::Error + Send + Sync>> + 'static,
    {
        match hyper::Response::builder()
            .status(code)
            .header("Content-Type", "application/json")
            .header("authentication", &self.authentication)
            .header("version", &self.version)
            .body(hyper::Body::wrap_stream(value))
        {
            Ok(resp) => resp,
            Err(e) => {
                tracing::error!("Error creating response: {}", e);
                hyper::Response::builder()
                    .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
                    .body(hyper::Body::empty())
                    .unwrap()
            }
        }
    }    
    
    pub async fn ok_stream<J, O, E>(&self, value: J) -> Result
    where
        J: Stream<Item = std::result::Result<O, E>> + Send + 'static,
        O: Into<Bytes> + 'static,
        E: Into<Box<dyn std::error::Error + Send + Sync>> + 'static,
    {
        self.create_stream(hyper::StatusCode::OK, value).await
    }

    
    fn create<T>(&self, code: hyper::StatusCode, value: &T) -> Result
    where
        T: ?Sized + Serialize + std::fmt::Debug,
    {
        match serde_json::to_string(value) {
            Ok(json) => {
                match hyper::Response::builder()
                    .status(code)
                    .header("Content-Type", "application/json")
                    .header("Content-Length", json.len())
                    .header("authentication", &self.authentication)
                    .header("version", &self.version)
                    .body(hyper::Body::from(json))
                {
                    Ok(resp) => resp,
                    Err(e) => {
                        tracing::error!("Error creating response: {}", e);
                        hyper::Response::builder()
                            .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
                            .body(hyper::Body::empty())
                            .unwrap()
                    }
                }
            }
            Err(e) => {
                tracing::error!("Error serializing response: {}", e);
                hyper::Response::builder()
                    .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
                    .body(hyper::Body::empty())
                    .unwrap()
            }
        }
    }
    
    pub fn ok<T>(&self, value: &T) -> Result
    where
        T: ?Sized + Serialize + std::fmt::Debug,
    {
        self.create(hyper::StatusCode::OK, value)
    }

    pub fn created<T>(&self, value: &T) -> Result
    where
        T: ?Sized + Serialize + std::fmt::Debug,
    {
        self.create(hyper::StatusCode::CREATED, value)
    }

    pub fn empty(&self, code: hyper::StatusCode) -> Result {
        hyper::Response::builder()
            .status(code)
            .header("authentication", &self.authentication)
            .header("version", &self.version)
            .body(hyper::Body::empty())
            .unwrap()
    }
    pub fn no_content(&self) -> Result {
        self.empty(hyper::StatusCode::NO_CONTENT)
    }

    pub fn unauthorized(&self) -> Result {
        self.empty(hyper::StatusCode::UNAUTHORIZED)
    }

    pub fn internal_server_error(&self, err: &dyn Error) -> Result {
        tracing::error!("Unexpected error: {}", err);
        self.empty(hyper::StatusCode::INTERNAL_SERVER_ERROR)
    }

    pub fn service_unavailable<'a>(&self, source: &'a str, reason: &'a str) -> Result {
        #[derive(Serialize, Debug)]
        struct Unavailable<'a> {
            source: &'a str,
            reason: &'a str,
        }
        let value = Unavailable { source, reason };
        tracing::error!("Service {} unavailable: {}", source, reason);
        self.create(hyper::StatusCode::SERVICE_UNAVAILABLE, &value)
    }

    pub fn not_found<'a>(&self, class: &'a str, id: &'a str) -> Result {
        #[derive(Serialize, Debug)]
        struct NotFound<'a> {
            class: &'a str,
            id: &'a str,
        }

        let value = NotFound { class, id };
        tracing::trace!("{:?}", value);
        self.create(hyper::StatusCode::NOT_FOUND, &value)
    }

    pub fn bad_request<T>(&self, value: &T) -> Result
    where
        T: ?Sized + Serialize + std::fmt::Debug,
    {
        self.create(hyper::StatusCode::BAD_REQUEST, &value)
    }

    pub fn not_accepted<T>(&self, got: &T, expected: &[T]) -> Result
    where
        T: Serialize + std::fmt::Debug,
    {
        #[derive(Serialize, Debug)]
        struct NotAccepted<'a, T> {
            allowed: &'a [T],
            got: &'a T,
        }
        let value = NotAccepted {
            allowed: expected,
            got,
        };
        self.create(hyper::StatusCode::NOT_ACCEPTABLE, &value)
    }
}
