use error::*;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::sign::Signer;
use std::io;
/// Hawk key.
///
/// While any sequence of bytes can be specified as a key, note that each digest algorithm has
/// a suggested key length, and that passwords should *not* be used as keys.  Keys of incorrect
/// length are handled according to the digest's implementation.
pub struct Key {
    key: PKey<Private>,
    digest: MessageDigest
}

pub(crate) struct SignedWriter<'a> {
    signer: Signer<'a>
}

impl<'a> SignedWriter<'a> {
    #[inline]
    pub(crate) fn new(signer: Signer<'a>) -> SignedWriter<'a> {
        SignedWriter { signer }
    }

    #[inline]
    fn finish_into(self, dest: &mut [u8]) -> Result<usize> {
        let len = self.signer.len()?;
        assert!(len <= dest.len());
        Ok(self.signer.sign(dest)?)
    }

    #[inline]
    pub(crate) fn finish_into_vec(self, dest: &mut Vec<u8>) -> Result<()> {
        dest.resize(self.signer.len()?, 0);
        // Note: signer.len() is upper bound (although it's possible for our use case
        // it will always be the same), so we truncate after.
        let wrote_len = self.finish_into(&mut dest[..])?;
        dest.truncate(wrote_len);
        Ok(())
    }
}

impl<'a> io::Write for SignedWriter<'a> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.signer.update(buf)?;
        Ok(buf.len())
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        // We don't buffer input (maybe we should?) so this is a no-op
        Ok(())
    }
}

impl Key {
    pub fn new<B>(key: B, digest: MessageDigest) -> Result<Key>
        where B: AsRef<[u8]>
    {
        let key = PKey::hmac(key.as_ref()).chain_err(|| "Key creation failed")?;
        Ok(Key {
            key,
            digest
        })
    }

    pub(crate) fn signer<'a>(&'a self) -> Result<SignedWriter<'a>> {
        Ok(SignedWriter::new(
            Signer::new(self.digest.clone(), &self.key)?))
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

    // It would be nice for Key::signer() and SignedWriter to get test coverage here
    // but ATM it's covered in `mac.rs`, which is probably fine for now.
}
