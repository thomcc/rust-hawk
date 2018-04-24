use error::*;
use openssl::hash::{Hasher, MessageDigest};

/// A utility for hashing payloads. Feed your entity body to this, then pass the `finish`
/// result to a request or response.
pub struct PayloadHasher {
    hasher: Hasher,
    digest: MessageDigest,
}

impl PayloadHasher {
    /// Create a new PayloadHasher. The `content_type` should be lower-case and should
    /// not include parameters. The digest is assumed to be the same as the digest used
    /// for the credentials in the request.
    pub fn new<B>(content_type: B, digest: MessageDigest) -> Result<Self>
        where B: AsRef<[u8]>
    {
        let hasher = Hasher::new(digest.clone()).chain_err(|| "Could not get hasher")?;
        let mut hasher = PayloadHasher {
            hasher,
            digest,
        };
        hasher.update(b"hawk.1.payload\n")?;
        hasher.update(content_type.as_ref())?;
        hasher.update(b"\n")?;
        Ok(hasher)
    }

    /// Hash a single value and return it
    pub fn hash<B1, B2>(content_type: B1,
                        digest: MessageDigest,
                        payload: B2)
                        -> Result<Vec<u8>>
        where B1: AsRef<[u8]>,
              B2: AsRef<[u8]>
    {
        let mut hasher = PayloadHasher::new(content_type, digest)?;
        hasher.update(payload)?;
        hasher.finish()
    }

    /// Update the hash with new data.
    pub fn update<B>(&mut self, data: B) -> Result<()>
        where B: AsRef<[u8]>
    {
        self.hasher.update(data.as_ref()).chain_err(|| "Could not feed data to hasher")?;
        Ok(())
    }

    /// Finish hashing and return the result
    ///
    /// Note that this appends a newline to the payload, as does the JS Hawk implementaiton.
    pub fn finish(mut self) -> Result<Vec<u8>> {
        self.update(b"\n")?;
        let digest = self.hasher.finish().chain_err(|| "Could get hasher data")?;
        let mut rv = vec![0; self.digest.size()];
        rv.clone_from_slice(digest.as_ref());
        Ok(rv)
    }
}

#[cfg(test)]
mod tests {
    use super::PayloadHasher;
    use openssl::hash::{MessageDigest};

    #[test]
    fn hash_consistency() {
        let mut hasher1 = PayloadHasher::new("text/plain", MessageDigest::sha256()).unwrap();
        hasher1.update("pày").unwrap();
        hasher1.update("load").unwrap();
        let hash1 = hasher1.finish().unwrap();

        let mut hasher2 = PayloadHasher::new("text/plain", MessageDigest::sha256()).unwrap();
        hasher2.update("pàyload").unwrap();
        let hash2 = hasher2.finish().unwrap();

        let hash3 = PayloadHasher::hash("text/plain", MessageDigest::sha256(), "pàyload").unwrap();

        let hash4 = // "pàyload" as utf-8 bytes
            PayloadHasher::hash("text/plain",
                                MessageDigest::sha256(), vec![112, 195, 160, 121, 108, 111, 97, 100]).unwrap();

        assert_eq!(hash1,
                   vec![228, 238, 241, 224, 235, 114, 158, 112, 211, 254, 118, 89, 25, 236, 87,
                        176, 181, 54, 61, 135, 42, 223, 188, 103, 194, 59, 83, 36, 136, 31, 198,
                        50]);
        assert_eq!(hash2, hash1);
        assert_eq!(hash3, hash1);
        assert_eq!(hash4, hash1);
    }
}
