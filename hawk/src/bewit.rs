use base64;
use mac::Mac;
use error::*;
use std::str;
use std::str::FromStr;
use time::Timespec;
use std::borrow::Cow;

/// A Bewit is a piece of data attached to a GET request that functions in place of a Hawk
/// Authentication header.  It contains an id, a timestamp, a MAC, and an optional `ext` value.
/// These are available using accessor functions.
#[derive(Clone, Debug)]
pub struct Bewit<'a> {
    id: Cow<'a, str>,
    exp: Timespec,
    mac: Cow<'a, Mac>,
    ext: Option<Cow<'a, str>>,
}

impl<'a> Bewit<'a> {
    /// Create a new Bewit with the given values.
    ///
    /// See Request.make_bewit for an easier way to make a Bewit
    pub fn new(id: &'a str, exp: Timespec, mac: Mac, ext: Option<&'a str>) -> Bewit<'a> {
        Bewit {
            id: Cow::Borrowed(id),
            exp: exp,
            mac: Cow::Owned(mac),
            ext: match ext {
                Some(s) => Some(Cow::Borrowed(s)),
                None => None,
            },
        }
    }

    /// Generate the fully-encoded string for this Bewit
    pub fn to_str(&self) -> String {
        let raw = format!("{}\\{}\\{}\\{}",
                          self.id,
                          self.exp.sec,
                          base64::encode(self.mac.as_ref()),
                          match self.ext {
                              Some(ref cow) => cow.as_ref(),
                              None => "",
                          });

        base64::encode_config(&raw, base64::URL_SAFE_NO_PAD)
    }

    /// Get the Bewit's client identifier
    pub fn id(&self) -> &str {
        self.id.as_ref()
    }

    /// Get the expiration time of the bewit
    pub fn exp(&self) -> Timespec {
        self.exp
    }

    /// Get the MAC included in the Bewit
    pub fn mac(&self) -> &Mac {
        self.mac.as_ref()
    }

    /// Get the Bewit's `ext` field.
    pub fn ext(&self) -> Option<&str> {
        match self.ext {
            Some(ref cow) => Some(cow.as_ref()),
            None => None,
        }
    }
}

const BACKSLASH: u8 = b'\\';

impl<'a> FromStr for Bewit<'a> {
    type Err = Error;
    fn from_str(bewit: &str) -> Result<Bewit<'a>> {
        let bewit = base64::decode(bewit).chain_err(|| "Error decoding bewit base64")?;

        let parts: Vec<&[u8]> = bewit.split(|c| *c == BACKSLASH).collect();
        if parts.len() != 4 {
            bail!("Invalid bewit format");
        }

        let id = String::from_utf8(parts[0].to_vec()).chain_err(|| "Invalid bewit id")?;

        let exp = str::from_utf8(parts[1]).chain_err(|| "Invalid bewit exp")?;
        let exp = i64::from_str(exp).chain_err(|| "Invalid bewit exp")?;
        let exp = Timespec::new(exp, 0);

        let mac = str::from_utf8(parts[2]).chain_err(|| "Invalid bewit mac")?;
        let mac = Mac::from(base64::decode(mac).chain_err(|| "Invalid bewit mac")?);

        let ext = match parts[3].len() {
            0 => None,
            _ => {
                Some(Cow::Owned(String::from_utf8(parts[3].to_vec())
                                    .chain_err(|| "Invalid bew,it ext")?))
            }
        };

        Ok(Bewit {
            id: Cow::Owned(id),
            exp: exp,
            mac: Cow::Owned(mac),
            ext: ext,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::str::FromStr;
    use credentials::Key;
    use openssl::hash::{MessageDigest};
    use mac::{Mac, MacType};

    fn make_mac() -> Mac {
        let key = Key::new(vec![11u8, 19, 228, 209, 79, 189, 200, 59, 166, 47, 86, 254, 235, 184,
                                120, 197, 75, 152, 201, 79, 115, 61, 111, 242, 219, 187, 173, 14,
                                227, 108, 60, 232],
                           MessageDigest::sha256()).unwrap();
        Mac::new(MacType::Header,
                 &key,
                 Timespec::new(1353832834, 100),
                 "nonny",
                 "POST",
                 "mysite.com",
                 443,
                 "/v1/api",
                 None,
                 None)
            .unwrap()
    }

    #[test]
    fn test_to_str() {
        let bewit = Bewit::new("me", Timespec::new(1353832834, 0), make_mac(), None);
        assert_eq!(bewit.to_str(),
                   "bWVcMTM1MzgzMjgzNFxmaXk0ZTV3QmRhcEROeEhIZUExOE5yU3JVMVUzaVM2NmdtMFhqVEpwWXlVPVw");
        let bewit = Bewit::new("me", Timespec::new(1353832834, 0), make_mac(), Some("abcd"));
        assert_eq!(bewit.to_str(),
                   "bWVcMTM1MzgzMjgzNFxmaXk0ZTV3QmRhcEROeEhIZUExOE5yU3JVMVUzaVM2NmdtMFhqVEpwWXlVPVxhYmNk");
    }

    #[test]
    fn test_accessors() {
        let bewit = Bewit::from_str("bWVcMTM1MzgzMjgzNFxmaXk0ZTV3QmRhcEROeEhIZUExOE5yU3JVMVUzaVM2NmdtMFhqVEpwWXlVPVw").unwrap();
        assert_eq!(bewit.id(), "me");
        assert_eq!(bewit.exp(), Timespec::new(1353832834, 0));
        assert_eq!(bewit.mac(), &make_mac());
        assert_eq!(bewit.ext(), None);
    }

    #[test]
    fn test_from_str_invalid_base64() {
        assert!(Bewit::from_str("!/==").is_err());
    }

    #[test]
    fn test_from_str_invalid_too_many_parts() {
        let bewit = base64::encode(&"a\\123\\abc\\ext\\WHUT?".as_bytes());
        assert!(Bewit::from_str(&bewit).is_err());
    }

    #[test]
    fn test_from_str_invalid_too_few_parts() {
        let bewit = base64::encode(&"a\\123\\abc".as_bytes());
        assert!(Bewit::from_str(&bewit).is_err());
    }

    #[test]
    fn test_from_str_invalid_not_utf8() {
        let a = 'a' as u8;
        let one = '1' as u8;
        let slash = '\\' as u8;
        let invalid1 = 0u8;
        let invalid2 = 159u8;
        let bewit = base64::encode(&[invalid1, invalid2, slash, one, slash, a, slash, a]);
        assert!(Bewit::from_str(&bewit).is_err());
        let bewit = base64::encode(&[a, slash, invalid1, invalid2, slash, a, slash, a]);
        assert!(Bewit::from_str(&bewit).is_err());
        let bewit = base64::encode(&[a, slash, one, slash, invalid1, invalid2, slash, a]);
        assert!(Bewit::from_str(&bewit).is_err());
        let bewit = base64::encode(&[a, slash, one, slash, a, slash, invalid1, invalid2]);
        assert!(Bewit::from_str(&bewit).is_err());
    }
}
