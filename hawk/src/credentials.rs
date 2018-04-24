use error::*;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::sign::Signer;

/// Hawk key.
///
/// While any sequence of bytes can be specified as a key, note that each digest algorithm has
/// a suggested key length, and that passwords should *not* be used as keys.  Keys of incorrect
/// length are handled according to the digest's implementation.
pub struct Key {
    key: PKey<Private>,
    digest: MessageDigest
}

impl Key {
    pub fn new<B>(key: B, digest: MessageDigest) -> Result<Key>
        where B: Into<Vec<u8>>
    {
        let key = PKey::hmac(key.into().as_ref()).chain_err(|| "Key creation failed")?;
        Ok(Key {
            key,
            digest
        })
    }

    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut hmac_signer = Signer::new(self.digest.clone(), &self.key)
            .chain_err(|| "Cannot instanciate HMAC signer.")?;
        hmac_signer.update(&data).chain_err(|| "Cannot feed data to signer.")?;
        let digest = hmac_signer.sign_to_vec().chain_err(|| "Cannot create signature.")?;
        let mut mac = vec![0; self.digest.size()];
        mac.clone_from_slice(digest.as_ref());
        Ok(mac)
    }
}

/// Hawk credentials: an ID and a key associated with that ID.  The digest algorithm
/// must be agreed between the server and the client, and the length of the key is
/// specific to that algorithm.
pub struct Credentials {
    pub id: String,
    pub key: Key,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_new_sha256() {
        let key = vec![77u8; 32];
        // hmac::SigningKey doesn't allow any visibilty inside, so we just build the
        // key and assume it works..
        Key::new(key, MessageDigest::sha256()).unwrap();
    }

    #[test]
    fn test_new_sha256_bad_length() {
        let key = vec![0u8; 99];
        Key::new(key, MessageDigest::sha256()).unwrap();
    }
}
