use credentials::Key;
use base64::display::Base64Display;
use openssl;
use std::fmt::{self, Display};
use std::io::Write;
use std::ops::Deref;
use std::borrow::Cow;
use error::*;
use time;

/// The kind of MAC calcuation (corresponding to the first line of the message)
#[derive(Clone, Copy, Debug)]
pub enum MacType {
    Header,
    Response,
    Bewit,
}

/// Mac represents a message authentication code, the signature in a Hawk transaction.
///
/// This class supports creating Macs using the Hawk specification, and comparing Macs
/// using a constant-time comparison (thus preventing timing side-channel attacks).
#[derive(Debug, Clone, Default)]
pub struct Mac(Vec<u8>);

#[derive(Debug, Clone)]
pub struct MacParams<'a> {
    pub mac_type: MacType,
    pub ts: time::Timespec,
    pub nonce: &'a str,
    pub method: &'a str,
    pub host: &'a str,
    pub port: u16,
    pub path: &'a str,
    pub hash: Option<&'a [u8]>,
    pub ext: Option<&'a str>,
}


impl<'a> Display for MacParams<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}\n", match self.mac_type {
            MacType::Header => "hawk.1.header",
            MacType::Response => "hawk.1.response",
            MacType::Bewit => "hawk.1.bewit",
        })?;
        write!(f, "{}\n", self.ts.sec)?;
        write!(f, "{}\n", self.nonce)?;
        write!(f, "{}\n", self.method)?;
        write!(f, "{}\n", self.path)?;
        write!(f, "{}\n", self.host)?;
        write!(f, "{}\n", self.port)?;

        if let Some(h) = self.hash {
            write!(f, "{}\n", Base64Display::standard(h))?;
        } else {
            write!(f, "\n")?;
        }

        match self.ext {
            Some(e) => write!(f, "{}\n", e),
            None => write!(f, "\n"),
        }
    }
}

impl Mac {

    #[deprecated(since="2.0.0", note="please use `new_signed` instead")]
    pub fn new(mac_type: MacType,
               key: &Key,
               ts: time::Timespec,
               nonce: &str,
               method: &str,
               host: &str,
               port: u16,
               path: &str,
               hash: Option<&[u8]>,
               ext: Option<&str>) -> Result<Mac> {
        let params = MacParams { mac_type, ts, nonce, method, host, port, path, hash, ext };
        Mac::new_signed(key, params)
    }

    pub fn new_signed(key: &Key, mac_params: MacParams) -> Result<Mac> {
        let mut mac = Mac(vec![]);
        mac.sign(key, mac_params)?;
        Ok(mac)
    }

    pub fn sign(&mut self, key: &Key, mac_params: MacParams) -> Result<()> {
        let mut signer = key.signer()?;
        write!(signer, "{}", mac_params)?;
        signer.finish_into_vec(&mut self.0)?;
        Ok(())
    }
}

impl AsRef<[u8]> for Mac {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl From<Vec<u8>> for Mac {
    fn from(original: Vec<u8>) -> Self {
        Mac(original)
    }
}

impl Deref for Mac {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl PartialEq for Mac {
    fn eq(&self, other: &Mac) -> bool {
        openssl::memcmp::eq(&self.0[..], &other.0[..])
    }
}

impl<'a> From<Mac> for Cow<'a, Mac> {
    #[inline]
    fn from(mac: Mac) -> Self {
        Cow::Owned(mac)
    }
}


#[cfg(test)]
mod test {
    use super::{Mac, MacType, MacParams};
    use time::Timespec;
    use credentials::Key;
    use openssl::hash::{MessageDigest};

    fn key() -> Key {
        Key::new(vec![11u8, 19, 228, 209, 79, 189, 200, 59, 166, 47, 86, 254, 235, 184, 120, 197,
                      75, 152, 201, 79, 115, 61, 111, 242, 219, 187, 173, 14, 227, 108, 60, 232],
                 MessageDigest::sha256()).unwrap()
    }

    #[test]
    fn test_make_mac() {
        let key = key();
        let mac = Mac::new_signed(&key,
                                  MacParams {
                                      mac_type: MacType::Header,
                                      ts: Timespec::new(1000, 100),
                                      nonce: "nonny",
                                      method: "POST",
                                      host: "mysite.com",
                                      port: 443,
                                      path: "/v1/api",
                                      hash: None,
                                      ext: None,
                                  }).unwrap();

        println!("got {:?}", mac);
        assert_eq!(mac.0,
                   vec![192, 227, 235, 121, 157, 185, 197, 79, 189, 214, 235, 139, 9, 232, 99, 55,
                        67, 30, 68, 0, 150, 187, 192, 238, 21, 200, 209, 107, 245, 159, 243, 178]);
    }

    #[test]
    fn test_make_mac_hash() {
        let key = key();
        let hash = vec![1, 2, 3, 4, 5];
        // Make sure that the lifetimes don't all need to be static
        let nonce = "nonny".to_string();
        let mac = Mac::new_signed(&key,
                                  MacParams {
                                      mac_type: MacType::Header,
                                      ts: Timespec::new(1000, 100),
                                      nonce: &nonce,
                                      method: "POST",
                                      host: "mysite.com",
                                      port: 443,
                                      path: "/v1/api",
                                      hash: Some(&hash),
                                      ext: None,
                                  }).unwrap();
        println!("got {:?}", mac);
        assert_eq!(mac.0,
                   vec![61, 128, 208, 253, 88, 135, 190, 196, 1, 69, 153, 193, 124, 4, 195, 87, 38,
                        96, 181, 34, 65, 234, 58, 157, 175, 175, 145, 151, 61, 0, 57, 5]);
    }

    #[test]
    fn test_make_mac_ext() {
        let key = key();
        let ext = "ext-data".to_string();
        let mut nonce = "nonny".to_string();
        let mac = Mac::new_signed(&key,
                                  MacParams {
                                      mac_type: MacType::Header,
                                      ts: Timespec::new(1000, 100),
                                      nonce: &nonce,
                                      method: "POST",
                                      host: "mysite.com",
                                      port: 443,
                                      path: "/v1/api",
                                      hash: None,
                                      ext: Some(&ext),
                                  }).unwrap();
        nonce += "Make sure that mac doesn't keep references to it's arguments";
        println!("got {:?}", mac);
        assert_eq!(mac.0,
                   vec![187, 104, 238, 100, 168, 112, 37, 68, 187, 141, 168, 155, 177, 193, 113, 0,
                        50, 105, 127, 36, 24, 117, 200, 251, 138, 199, 108, 14, 105, 123, 234, 119]);
    }

    #[test]
    fn test_reuse_mac() {
        let key = key();
        let mut mac = Mac::default();
        // Sign it once with data we don't care about -- we expect this to be clobbered by data
        // we do care about
        mac.sign(&key,
                 MacParams {
                     mac_type: MacType::Header,
                     ts: Timespec::new(1000, 100),
                     nonce: "garbage",
                     method: "GET",
                     host: "whatever.com",
                     port: 443,
                     path: "/stuff",
                     hash: Some(&[1, 2, 3]),
                     ext: Some("foobar"),
                 }).unwrap();

        mac.sign(&key,
                 MacParams {
                     mac_type: MacType::Header,
                     ts: Timespec::new(1000, 100),
                     nonce: "nonny",
                     method: "POST",
                     host: "mysite.com",
                     port: 443,
                     path: "/v1/api",
                     hash: None,
                     ext: None,
                 }).unwrap();
        println!("got {:?}", mac);
        assert_eq!(mac.0,
                   vec![192, 227, 235, 121, 157, 185, 197, 79, 189, 214, 235, 139, 9, 232, 99, 55,
                        67, 30, 68, 0, 150, 187, 192, 238, 21, 200, 209, 107, 245, 159, 243, 178]);
    }
}
