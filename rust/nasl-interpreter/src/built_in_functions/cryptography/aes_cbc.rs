// Copyright (C) 2023 Greenbone Networks GmbH
//
// SPDX-License-Identifier: GPL-2.0-or-later

use aes::{
    cipher::{
        block_padding::{NoPadding, ZeroPadding},
        BlockCipher, BlockDecrypt, BlockDecryptMut, BlockEncrypt, BlockEncryptMut, KeyInit,
        KeyIvInit,
    },
    Aes128, Aes192, Aes256,
};
use cbc::{Decryptor, Encryptor};

use crate::{
    error::{FunctionError, FunctionErrorKind::GeneralError},
    Context, NaslFunction, NaslValue, Register,
};

use super::{get_named_data, get_named_number, Crypt};

/// Base function for en- and decrypting Cipher Block Chaining (CBC) mode
fn cbc<D>(register: &Register, crypt: Crypt, function: &str) -> Result<NaslValue, FunctionError>
where
    D: BlockCipher + BlockEncrypt + BlockDecrypt + KeyInit,
{
    // Get Arguments
    let key = get_named_data(register, "key", true, function)?.unwrap();
    let data = get_named_data(register, "data", true, function)?.unwrap();
    let iv = get_named_data(register, "iv", true, function)?.unwrap();
    let len = match get_named_number(register, "len", false, function)? {
        Some(x) => match usize::try_from(x) {
            Ok(x) => x,
            Err(_) => {
                return Err(FunctionError::new(
                    function,
                    GeneralError(format!(
                        "System only supports numbers between {:?} and {:?}",
                        usize::MIN,
                        usize::MAX
                    )),
                ))
            }
        },
        None => data.len(),
    };

    // len should not be more than the length of the data
    if len > data.len() {
        return Err(FunctionError::new(
            function,
            (
                "len",
                format!("<={:?}", data.len()).as_str(),
                len.to_string().as_str(),
            )
                .into(),
        ));
    }

    // Mode Encrypt or Decrypt
    match crypt {
        Crypt::Encrypt => {
            let res = Encryptor::<D>::new_from_slices(key, iv);
            match res {
                Ok(encryptor) => {
                    return Ok(encryptor.encrypt_padded_vec_mut::<ZeroPadding>(data).into())
                }
                Err(e) => {
                    return Err(FunctionError::new(
                        function,
                        crate::error::FunctionErrorKind::WrongArgument(e.to_string()),
                    ))
                }
            };
        }
        Crypt::Decrypt => {
            let res = Decryptor::<D>::new_from_slices(key, iv);
            match res {
                Ok(decryptor) => {
                    return Ok(
                        decryptor.decrypt_padded_vec_mut::<NoPadding>(data).unwrap()[..len]
                            .to_vec()
                            .into(),
                    )
                }
                Err(e) => {
                    return Err(FunctionError::new(
                        function,
                        crate::error::FunctionErrorKind::WrongArgument(e.to_string()),
                    ))
                }
            };
        }
    }
}

/// NASL function to encrypt data with aes128 cbc.
///
/// This function expects 3 named arguments key, data and iv either in a string or data type.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes
fn aes128_cbc_encrypt<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionError> {
    cbc::<Aes128>(register, Crypt::Encrypt, "aes128_cbc_encrypt")
}

/// NASL function to decrypt data with aes128 cbc.
///
/// This function expects 4 named arguments key, data and iv either in a string or data type. The
/// len argument is a number.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes
fn aes128_cbc_decrypt<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionError> {
    cbc::<Aes128>(register, Crypt::Decrypt, "aes128_cbc_decrypt")
}

/// NASL function to encrypt data with aes192 cbc.
///
/// This function expects 3 named arguments key, data and iv either in a string or data type.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes
fn aes192_cbc_encrypt<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionError> {
    cbc::<Aes192>(register, Crypt::Encrypt, "aes192_cbc_encrypt")
}

/// NASL function to decrypt data with aes192 cbc.
///
/// This function expects 4 named arguments key, data and iv either in a string or data type. The
/// len argument is a number.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes
fn aes192_cbc_decrypt<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionError> {
    cbc::<Aes192>(register, Crypt::Decrypt, "aes192_cbc_decrypt")
}

/// NASL function to encrypt data with aes256 cbc.
///
/// This function expects 3 named arguments key, data and iv either in a string or data type.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes
fn aes256_cbc_encrypt<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionError> {
    cbc::<Aes256>(register, Crypt::Encrypt, "aes256_cbc_encrypt")
}

/// NASL function to decrypt data with aes256 cbc.
///
/// This function expects 4 named arguments key, data and iv either in a string or data type. The
/// len argument is a number.
/// - The data is divided into blocks of 16 bytes. The last block is filled so it also has 16 bytes.
///   Currently the data is filled with zeroes. Therefore the length of the encrypted data must be
///   known for decryption. If no length is given, the last block is decrypted as a whole.
/// - The iv must have a length of 16 bytes
fn aes256_cbc_decrypt<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionError> {
    cbc::<Aes256>(register, Crypt::Decrypt, "aes256_cbc_decrypt")
}

pub fn lookup<K>(key: &str) -> Option<NaslFunction<K>> {
    match key {
        "aes128_cbc_encrypt" => Some(aes128_cbc_encrypt),
        "aes128_cbc_decrypt" => Some(aes128_cbc_decrypt),
        "aes192_cbc_encrypt" => Some(aes192_cbc_encrypt),
        "aes192_cbc_decrypt" => Some(aes192_cbc_decrypt),
        "aes256_cbc_encrypt" => Some(aes256_cbc_encrypt),
        "aes256_cbc_decrypt" => Some(aes256_cbc_decrypt),
        _ => None,
    }
}

#[cfg(test)]
mod tests {

    use nasl_syntax::parse;

    use crate::{helper::decode_hex, DefaultContext, Interpreter, Register};

    #[test]
    fn aes128_cbc_crypt() {
        let code = r###"
        key = hexstr_to_data("00000000000000000000000000000000");
        data = hexstr_to_data("80000000000000000000000000000000");
        iv = hexstr_to_data("00000000000000000000000000000000");
        crypt = aes128_cbc_encrypt(key: key, data: data, iv: iv);
        aes128_cbc_decrypt(key: key, data: crypt, iv: iv);
        "###;
        let mut register = Register::default();
        let binding = DefaultContext::default();
        let context = binding.as_context();
        let mut interpreter = Interpreter::new(&mut register, &context);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        parser.next();
        parser.next();
        parser.next();
        assert_eq!(
            parser.next(),
            Some(Ok(crate::NaslValue::Data(
                decode_hex("3ad78e726c1ec02b7ebfe92b23d9ec34").unwrap()
            )))
        );
        assert_eq!(
            parser.next(),
            Some(Ok(crate::NaslValue::Data(
                decode_hex("80000000000000000000000000000000").unwrap()
            )))
        );
    }

    #[test]
    fn aes192_cbc_crypt() {
        let code = r###"
        key = hexstr_to_data("000000000000000000000000000000000000000000000000");
        data = hexstr_to_data("1b077a6af4b7f98229de786d7516b639");
        iv = hexstr_to_data("00000000000000000000000000000000");
        crypt = aes192_cbc_encrypt(key: key, data: data, iv: iv);
        aes192_cbc_decrypt(key: key, data: crypt, iv: iv);
        "###;
        let mut register = Register::default();
        let binding = DefaultContext::default();
        let context = binding.as_context();
        let mut interpreter = Interpreter::new(&mut register, &context);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        parser.next();
        parser.next();
        parser.next();
        assert_eq!(
            parser.next(),
            Some(Ok(crate::NaslValue::Data(
                decode_hex("275cfc0413d8ccb70513c3859b1d0f72").unwrap()
            )))
        );
        assert_eq!(
            parser.next(),
            Some(Ok(crate::NaslValue::Data(
                decode_hex("1b077a6af4b7f98229de786d7516b639").unwrap()
            )))
        );
    }

    #[test]
    fn aes256_cbc_crypt() {
        let code = r###"
        key = hexstr_to_data("0000000000000000000000000000000000000000000000000000000000000000");
        data = hexstr_to_data("014730f80ac625fe84f026c60bfd547d");
        iv = hexstr_to_data("00000000000000000000000000000000");
        crypt = aes256_cbc_encrypt(key: key, data: data, iv: iv);
        aes256_cbc_decrypt(key: key, data: crypt, iv: iv);
        "###;
        let mut register = Register::default();
        let binding = DefaultContext::default();
        let context = binding.as_context();
        let mut interpreter = Interpreter::new(&mut register, &context);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        parser.next();
        parser.next();
        parser.next();
        assert_eq!(
            parser.next(),
            Some(Ok(crate::NaslValue::Data(
                decode_hex("5c9d844ed46f9885085e5d6a4f94c7d7").unwrap()
            )))
        );
        assert_eq!(
            parser.next(),
            Some(Ok(crate::NaslValue::Data(
                decode_hex("014730f80ac625fe84f026c60bfd547d").unwrap()
            )))
        );
    }

    #[test]
    fn padding() {
        let code = r###"
        key = hexstr_to_data("00000000000000000000000000000000");
        data1 = hexstr_to_data("f34481ec3cc627bacd5dc3fb08f2");
        data2 = hexstr_to_data("f34481ec3cc627bacd5dc3fb08f20000");
        iv = hexstr_to_data("00000000000000000000000000000000");
        aes128_cbc_encrypt(key: key, data: data1, iv: iv);
        aes128_cbc_encrypt(key: key, data: data2, iv: iv);
        "###;
        let mut register = Register::default();
        let binding = DefaultContext::default();
        let context = binding.as_context();
        let mut interpreter = Interpreter::new(&mut register, &context);
        let mut parser =
            parse(code).map(|x| interpreter.resolve(&x.expect("no parse error expected")));
        parser.next();
        parser.next();
        parser.next();
        parser.next();
        let crypt1 = parser.next();
        let crypt2 = parser.next();
        assert_eq!(crypt1, crypt2);
    }
}