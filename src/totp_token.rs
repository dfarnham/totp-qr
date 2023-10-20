use crate::otpauth_migration;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use std::error::Error;

// Create aliases
type HmacSha1 = Hmac<sha1::Sha1>;
type HmacSha256 = Hmac<sha2::Sha256>;
type HmacSha512 = Hmac<sha2::Sha512>;

/// Algorithm enum holds the three standards algorithms for TOTP as per the
/// [reference implementation](https://tools.ietf.org/html/rfc6238#appendix-A)
enum Algorithm {
    SHA1,
    SHA256,
    SHA512,
}
impl Algorithm {
    fn hash<D: Mac>(mut hmac: D, msg: &[u8]) -> Vec<u8> {
        hmac.update(msg);
        hmac.finalize().into_bytes().to_vec()
    }

    fn sign(&self, key: &[u8], msg: &[u8]) -> Vec<u8> {
        match self {
            Self::SHA1 => Self::hash(HmacSha1::new_from_slice(key).unwrap(), msg),
            Self::SHA256 => Self::hash(HmacSha256::new_from_slice(key).unwrap(), msg),
            Self::SHA512 => Self::hash(HmacSha512::new_from_slice(key).unwrap(), msg),
        }
    }

    fn supply(sha_name: Option<String>) -> Self {
        match sha_name {
            Some(name) if name.eq_ignore_ascii_case("SHA256") => Self::SHA256,
            Some(name) if name.eq_ignore_ascii_case("SHA512") => Self::SHA512,
            _ => Self::SHA1,
        }
    }
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct Account {
    pub secret: String,
    pub issuer: String,
    pub sha: String,
    pub digits: u32,
    pub period: u64,
}

/// Return the named parameter value fron an otpauth string
fn uri_param(otpauth: &str, name: &str) -> Option<String> {
    match otpauth.split(name).nth(1)?.split('&').next().map(urlencoding::decode)? {
        Ok(s) => Some(s.into()),
        _ => None,
    }
}

/// Returns a list of Account
///
/// otpauth can be 1 of 2 forms:
///
///   1. "otpauth-migration://offline" -- Protobuf of exported Accounts
///   2. "otpauth://totp" -- String with Base-32 encoded Secret
pub fn get_accounts(otpauth: &str) -> Result<Vec<Account>, Box<dyn Error>> {
    match otpauth.contains("otpauth-migration://offline") {
        true => otpauth_migration::get_accounts(otpauth),
        false => {
            // Secret -- required
            let secret = uri_param(otpauth, "secret=").ok_or(format!("missing secret, otpauth = {otpauth}"))?;

            // Issuer -- default ""
            let issuer = uri_param(otpauth, "issuer=").unwrap_or_default();

            // Algorithm -- default "SHA1"
            let sha = uri_param(otpauth, "algorithm=").unwrap_or("SHA1".into());

            // Digits -- default 6
            let digits = match uri_param(otpauth, "digits=") {
                Some(s) if s == "8" => 8,
                _ => 6,
            };

            // Period -- default 30
            let period = match uri_param(otpauth, "period=") {
                Some(s) => s.parse()?,
                _ => 30,
            };

            Ok(vec![Account {
                secret,
                issuer,
                sha,
                digits,
                period,
            }])
        }
    }
}

/// Generate a time based token from the Base-32 secret and Algorithm
pub fn time_token(time: u64, account: &Account) -> Result<String, Box<dyn Error>> {
    let alphabet = base32::Alphabet::RFC4648 { padding: false };
    let secret_bytes = base32::decode(alphabet, &account.secret).ok_or("base32::decode failed")?;
    let algorithm = Algorithm::supply(Some(account.sha.to_string()));
    let bytes = algorithm.sign(&secret_bytes, &(time / account.period).to_be_bytes());
    match bytes.last() {
        Some(n) => {
            let offset = (n & 0xf) as usize;
            let result = u32::from_be_bytes(bytes[offset..offset + 4].try_into()?);
            let token = (result & 0x7fff_ffff) % 10_u32.pow(account.digits);
            Ok(format!("{token:0>width$}", width = account.digits as usize))
        }
        _ => Err("time_token(): failed".into()),
    }
}
