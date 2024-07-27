use anyhow::Result;
use hmac::{Hmac, Mac};
use sha1::Sha1;

pub const SHA1_DIGEST_BYTES: usize = 20;

pub fn hmac_sha1(key: &[u8], message: &[u8]) -> Result<[u8; SHA1_DIGEST_BYTES]> {
    let mut hasher: Hmac<Sha1> = Mac::new_from_slice(key)?;
    hasher.update(message);
    Ok(hasher.finalize().into_bytes().into())
}
