// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::{
    fs::File,
    io::{self, Read},
    path::Path,
};

use models::Advisories;

use crate::error::Error;

use super::AdvisoriesLoader;

#[derive(Debug, Clone)]
pub struct JSONAdvisoryLoader<P>
where
    P: AsRef<Path>,
{
    path: P,
}

impl<P> JSONAdvisoryLoader<P>
where
    P: AsRef<Path>,
{
    pub fn new(path: P) -> Result<Self, Error> {
        if !path.as_ref().exists() {
            return Err(Error::MissingAdvisoryDir(
                path.as_ref().to_string_lossy().to_string(),
            ));
        }

        if !path.as_ref().is_dir() {
            return Err(Error::AdvisoryDirIsFile(
                path.as_ref().to_string_lossy().to_string(),
            ));
        }

        Ok(Self { path })
    }
}

impl<P> AdvisoriesLoader for JSONAdvisoryLoader<P>
where
    P: AsRef<Path>,
{
    fn load_package_advisories(&self, os: &str) -> Result<Advisories, Error> {
        let notus_file = self.path.as_ref().join(format!("{os}.notus"));
        let notus_file_str = notus_file.to_string_lossy().to_string();
        let mut file = match File::open(notus_file) {
            Ok(file) => file,
            Err(err) => {
                if matches!(err.kind(), io::ErrorKind::NotFound) {
                    return Err(Error::UnknownOs(os.to_string()));
                }
                return Err(Error::LoadAdvisoryError(notus_file_str, err));
            }
        };
        let mut buf = String::new();
        if let Err(err) = file.read_to_string(&mut buf) {
            return Err(Error::LoadAdvisoryError(notus_file_str, err));
        }
        match serde_json::from_str(&buf) {
            Ok(adv) => Ok(adv),
            Err(err) => Err(Error::JSONParseError(notus_file_str, err)),
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::{error::Error, loader::AdvisoriesLoader};

    use super::JSONAdvisoryLoader;

    #[test]
    fn test_load_advisories() {
        let mut path = env!("CARGO_MANIFEST_DIR").to_string();
        path.push_str("/data");
        let loader = JSONAdvisoryLoader::new(path).unwrap();
        let _ = loader.load_package_advisories("debian_10").unwrap();
    }

    #[test]
    fn test_err_missing_advisory_dir() {
        let mut path = env!("CARGO_MANIFEST_DIR").to_string();
        path.push_str("/data_foo");
        assert!(
            matches!(JSONAdvisoryLoader::new(path.clone()).expect_err("Should fail"), Error::MissingAdvisoryDir(p) if p == path)
        );
    }

    #[test]
    fn test_err_advisory_dir_is_file() {
        let mut path = env!("CARGO_MANIFEST_DIR").to_string();
        path.push_str("/data/debian_10.notus");
        assert!(
            matches!(JSONAdvisoryLoader::new(path.clone()).expect_err("Should fail"), Error::AdvisoryDirIsFile(p) if p == path)
        );
    }

    #[test]
    fn test_err_unknown_os() {
        let mut path = env!("CARGO_MANIFEST_DIR").to_string();
        path.push_str("/data");
        let loader = JSONAdvisoryLoader::new(path).unwrap();

        let os = "foo";
        assert!(
            matches!(loader.load_package_advisories(os).expect_err("Should fail"), Error::UnknownOs(o) if o == os)
        );
    }

    #[test]
    fn test_err_json_parse() {
        let mut path = env!("CARGO_MANIFEST_DIR").to_string();
        path.push_str("/data");
        let loader = JSONAdvisoryLoader::new(path.clone()).unwrap();

        let os = "debian_10_json_parse_err";
        assert!(
            matches!(loader.load_package_advisories(os).expect_err("Should fail"), Error::JSONParseError(p, _) if p == format!("{path}/{os}.notus"))
        );
    }
}
