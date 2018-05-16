use base64::{self, display::Base64Display};
use std::fmt;
use std::str::FromStr;
use mac::Mac;
use error::*;
use time::Timespec;
use std::borrow::Cow;

/// Representation of a Hawk `Authorization` header value (the part following "Hawk ").
///
/// Headers can be derived froms trings using the `FromStr` trait, and formatted into a
/// string using the `fmt_header` method.
///
/// All fields are optional, although for specific purposes some fields must be present.
#[derive(Clone, PartialEq, Debug, Default)]
pub struct Header<'a> {
    pub id: Option<Cow<'a, str>>,
    pub ts: Option<Timespec>,
    pub nonce: Option<Cow<'a, str>>,
    pub mac: Option<Cow<'a, Mac>>,
    pub ext: Option<Cow<'a, str>>,
    pub hash: Option<Cow<'a, [u8]>>,
    pub app: Option<Cow<'a, str>>,
    pub dlg: Option<Cow<'a, str>>,
}

impl<'a> Header<'a> {

    #[inline]
    pub fn with_ts(mut self, ts: Option<Timespec>) -> Header<'a> {
        self.ts = ts;
        self
    }

    #[inline]
    pub fn with_mac(mut self, mac: Option<impl Into<Cow<'a, Mac>>>) -> Header<'a> {
        self.mac = mac.map(|m| m.into());
        self
    }

    #[inline]
    pub fn with_hash(mut self, hash: Option<impl Into<Cow<'a, [u8]>>>) -> Header<'a> {
        self.hash = hash.map(|h| h.into());
        self
    }

    #[inline]
    pub fn with_id(mut self, id: Option<impl Into<Cow<'a, str>>>) -> Result<Header<'a>> {
        self.id = Header::check_component(id)?;
        Ok(self)
    }

    #[inline]
    pub fn with_nonce(mut self, nonce: Option<impl Into<Cow<'a, str>>>) -> Result<Header<'a>> {
        self.nonce = Header::check_component(nonce)?;
        Ok(self)
    }

    #[inline]
    pub fn with_app(mut self, app: Option<impl Into<Cow<'a, str>>>) -> Result<Header<'a>> {
        self.app = Header::check_component(app)?;
        Ok(self)
    }


    #[inline]
    pub fn with_dlg(mut self, dlg: Option<impl Into<Cow<'a, str>>>) -> Result<Header<'a>> {
        self.dlg = Header::check_component(dlg)?;
        Ok(self)
    }

    #[inline]
    pub fn with_ext(mut self, ext: Option<impl Into<Cow<'a, str>>>) -> Result<Header<'a>> {
        self.ext = Header::check_component(ext)?;
        Ok(self)
    }

    /// Check a header component for validity.
    fn check_component(value: Option<impl Into<Cow<'a, str>>>) -> Result<Option<Cow<'a, str>>> {
        if let Some(value) = value {
            let value = value.into();
            if value.contains('\"') {
                bail!("Hawk headers cannot contain `\\`");
            }
            Ok(Some(value))
        } else {
            Ok(None)
        }
    }

    /// Format the header for transmission in an Authorization header, omitting the `"Hawk "`
    /// prefix.
    pub fn fmt_header(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut sep = "";
        if let Some(ref id) = self.id {
            write!(f, "{}id=\"{}\"", sep, id)?;
            sep = ", ";
        }
        if let Some(ref ts) = self.ts {
            write!(f, "{}ts=\"{}\"", sep, ts.sec)?;
            sep = ", ";
        }
        if let Some(ref nonce) = self.nonce {
            write!(f, "{}nonce=\"{}\"", sep, nonce)?;
            sep = ", ";
        }
        if let Some(ref mac) = self.mac {
            write!(f, "{}mac=\"{}\"", sep, Base64Display::standard(mac))?;
            sep = ", ";
        }
        if let Some(ref ext) = self.ext {
            write!(f, "{}ext=\"{}\"", sep, ext)?;
            sep = ", ";
        }
        if let Some(ref hash) = self.hash {
            write!(f, "{}hash=\"{}\"", sep, Base64Display::standard(hash))?;
            sep = ", ";
        }
        if let Some(ref app) = self.app {
            write!(f, "{}app=\"{}\"", sep, app)?;
            sep = ", ";
        }
        if let Some(ref dlg) = self.dlg {
            write!(f, "{}dlg=\"{}\"", sep, dlg)?;
        }
        Ok(())
    }
}

impl<'a> fmt::Display for Header<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.fmt_header(f)
    }
}

impl FromStr for Header<'static> {
    type Err = Error;
    fn from_str(mut p: &str) -> Result<Header<'static>> {
        let mut result = Header::default();
        // Required attributes

        while !p.is_empty() {
            // Skip whitespace and commas used as separators
            p = p.trim_left_matches(|c| c == ',' || char::is_whitespace(c));
            // Find first '=' which delimits attribute name from value
            match p.find('=') {
                Some(v) => {
                    let attr = &p[..v].trim();
                    if p.len() < v + 1 {
                        bail!(ErrorKind::HeaderParseError);
                    }
                    p = (&p[v + 1..]).trim_left();
                    if !p.starts_with('\"') {
                        bail!(ErrorKind::HeaderParseError);
                    }
                    p = &p[1..];
                    // We have poor RFC 7235 compliance here as we ought to support backslash
                    // escaped characters, but hawk doesn't allow this we won't either.  All
                    // strings must be surrounded by ".." and contain no such characters.
                    let end = p.find('\"');
                    match end {
                        Some(v) => {
                            let val = &p[..v];
                            match *attr {
                                "id" => {
                                    result = result.with_id(Some(val.to_string()))?;
                                }
                                "ts" => {
                                    let epoch = i64::from_str(val)
                                        .chain_err(|| "Error parsing `ts` field")?;
                                    result = result.with_ts(Some(Timespec::new(epoch, 0)));
                                }
                                "mac" => {
                                    result = result.with_mac(Some(
                                        Cow::Owned(
                                            base64::decode(val)
                                                .chain_err(|| "Error parsing `mac` field")?
                                                .into())));
                                }
                                "nonce" => {
                                    result = result.with_nonce(Some(val.to_string()))?;
                                }
                                "ext" => {
                                    result = result.with_ext(Some(val.to_string()))?;
                                }
                                "hash" => {
                                    result = result.with_hash(Some(base64::decode(val)
                                                    .chain_err(|| "Error parsing `hash` field")?));
                                }
                                "app" => {
                                    result = result.with_app(Some(val.to_string()))?;
                                }
                                "dlg" => {
                                    result = result.with_dlg(Some(val.to_string()))?;
                                }
                                _ => bail!("Invalid Hawk field {}", *attr),
                            };
                            // Break if we are at end of string, otherwise skip separator
                            if p.len() < v + 1 {
                                break;
                            }
                            p = p[v + 1..].trim_left();
                        }
                        None => bail!(ErrorKind::HeaderParseError),
                    }
                }
                None => bail!(ErrorKind::HeaderParseError),
            };
        }
        Ok(result)
    }
}

#[cfg(test)]
mod test {
    use super::Header;
    use time::Timespec;
    use std::str::FromStr;
    use mac::Mac;

    #[test]
    fn illegal_id() {
        assert!(Header::default().with_id(Some("ab\"cdef")).is_err());
    }

    #[test]
    fn illegal_nonce() {
        assert!(Header::default().with_nonce(Some("no\"nce")).is_err());
    }

    #[test]
    fn illegal_ext() {
        assert!(Header::default().with_ext(Some("ex\"t")).is_err());
    }

    #[test]
    fn illegal_app() {
        assert!(Header::default().with_app(Some("ap\"p")).is_err());
    }


    #[test]
    fn illegal_dlg() {
        assert!(Header::default().with_dlg(Some("dl\"g")).is_err());
    }

    #[test]
    fn from_str() {
        let s = Header::from_str("id=\"dh37fgj492je\", ts=\"1353832234\", \
                                      nonce=\"j4h3g2\", ext=\"some-app-ext-data\", \
                                      mac=\"6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE=\", \
                                      hash=\"6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE=\", \
                                      app=\"my-app\", dlg=\"my-authority\"")
            .unwrap();
        assert_eq!(s.id.unwrap(), "dh37fgj492je");
        assert!(s.ts == Some(Timespec::new(1353832234, 0)));
        assert_eq!(s.nonce.unwrap(), "j4h3g2");
        assert_eq!(s.mac.unwrap().as_ref(),
                   &Mac::from(vec![233, 30, 43, 87, 152, 132, 248, 211, 232, 202, 111, 150,
                                   194, 55, 135, 206, 48, 6, 93, 75, 75, 52, 140, 102, 163,
                                   91, 233, 50, 135, 233, 44, 1]));
        assert_eq!(s.ext.unwrap(), "some-app-ext-data");
        assert_eq!(s.app.unwrap(), "my-app");
        assert_eq!(s.dlg.unwrap(), "my-authority");
    }

    #[test]
    fn from_str_invalid_mac() {
        let r = Header::from_str("id=\"dh37fgj492je\", ts=\"1353832234\", \
                                      nonce=\"j4h3g2\", ext=\"some-app-ext-data\", \
                                      mac=\"6!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!AE=\", \
                                      app=\"my-app\", dlg=\"my-authority\"");
        assert!(r.is_err());
    }

    #[test]
    fn from_str_no_field() {
        let s = Header::from_str("").unwrap();
        assert!(s.id == None);
        assert!(s.ts == None);
        assert!(s.nonce == None);
        assert!(s.mac == None);
        assert!(s.ext == None);
        assert!(s.app == None);
        assert!(s.dlg == None);
    }

    #[test]
    fn from_str_few_field() {
        let s = Header::from_str("id=\"xyz\", ts=\"1353832234\", \
                                      nonce=\"abc\", \
                                      mac=\"6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE=\"")
            .unwrap();
        assert_eq!(s.id.unwrap(), "xyz");
        assert!(s.ts == Some(Timespec::new(1353832234, 0)));
        assert_eq!(s.nonce.unwrap(), "abc");
        assert_eq!(s.mac.unwrap().as_ref(),
                   &Mac::from(vec![233, 30, 43, 87, 152, 132, 248, 211, 232, 202, 111, 150,
                                   194, 55, 135, 206, 48, 6, 93, 75, 75, 52, 140, 102, 163,
                                   91, 233, 50, 135, 233, 44, 1]));
        assert!(s.ext == None);
        assert!(s.app == None);
        assert!(s.dlg == None);
    }

    #[test]
    fn from_str_messy() {
        let s = Header::from_str(", id  =  \"dh37fgj492je\", ts=\"1353832234\", \
                                      nonce=\"j4h3g2\"  , , ext=\"some-app-ext-data\", \
                                      mac=\"6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE=\"")
            .unwrap();
        assert_eq!(s.id.unwrap(), "dh37fgj492je");
        assert!(s.ts == Some(Timespec::new(1353832234, 0)));
        assert_eq!(s.nonce.unwrap(), "j4h3g2");
        assert_eq!(s.mac.unwrap().as_ref(),
                   &Mac::from(vec![233, 30, 43, 87, 152, 132, 248, 211, 232, 202, 111, 150,
                                   194, 55, 135, 206, 48, 6, 93, 75, 75, 52, 140, 102, 163,
                                   91, 233, 50, 135, 233, 44, 1]));
        assert_eq!(s.ext.unwrap(), "some-app-ext-data");
        assert!(s.app == None);
        assert!(s.dlg == None);
    }

    #[test]
    fn to_str_no_fields() {
        // must supply a type for S, since it is otherwise unused
        let s: Header<'static> = Header::default();
        let formatted = format!("{}", s);
        println!("got: {}", formatted);
        assert!(formatted == "")
    }

    #[test]
    fn to_str_few_fields() {
        let s = Header::default()
            .with_id(Some("dh37fgj492je")).unwrap()
            .with_ts(Some(Timespec::new(1353832234, 0)))
            .with_nonce(Some("j4h3g2")).unwrap()
            .with_mac(Some(Mac::from(vec![8, 35, 182, 149, 42, 111, 33, 192, 19, 22, 94,
                                          43, 118, 176, 65, 69, 86, 4, 156, 184, 85, 107,
                                          249, 242, 172, 200, 66, 209, 57, 63, 38, 83])));
        let formatted = format!("{}", s);
        println!("got: {}", formatted);
        assert!(formatted ==
                "id=\"dh37fgj492je\", ts=\"1353832234\", nonce=\"j4h3g2\", \
                 mac=\"CCO2lSpvIcATFl4rdrBBRVYEnLhVa/nyrMhC0Tk/JlM=\"")
    }

    #[test]
    fn to_str_maximal() {
        let s = Header::default()
            .with_id(Some("dh37fgj492je")).unwrap()
            .with_ts(Some(Timespec::new(1353832234, 0)))
            .with_nonce(Some("j4h3g2")).unwrap()
            .with_mac(Some(Mac::from(vec![8, 35, 182, 149, 42, 111, 33, 192, 19, 22, 94,
                                          43, 118, 176, 65, 69, 86, 4, 156, 184, 85, 107,
                                          249, 242, 172, 200, 66, 209, 57, 63, 38, 83])))
            .with_ext(Some("my-ext-value")).unwrap()
            .with_hash(Some(vec![1, 2, 3, 4]))
            .with_app(Some("my-app")).unwrap()
            .with_dlg(Some("my-dlg")).unwrap();
        let formatted = format!("{}", s);
        println!("got: {}", formatted);
        assert!(formatted ==
                "id=\"dh37fgj492je\", ts=\"1353832234\", nonce=\"j4h3g2\", \
                 mac=\"CCO2lSpvIcATFl4rdrBBRVYEnLhVa/nyrMhC0Tk/JlM=\", ext=\"my-ext-value\", \
                 hash=\"AQIDBA==\", app=\"my-app\", dlg=\"my-dlg\"")
    }

    #[test]
    fn round_trip() {
        let s = Header::default()
            .with_id(Some("dh37fgj492je")).unwrap()
            .with_ts(Some(Timespec::new(1353832234, 0)))
            .with_nonce(Some("j4h3g2")).unwrap()
            .with_mac(Some(Mac::from(vec![8, 35, 182, 149, 42, 111, 33, 192, 19, 22, 94,
                                          43, 118, 176, 65, 69, 86, 4, 156, 184, 85, 107,
                                          249, 242, 172, 200, 66, 209, 57, 63, 38, 83])))
            .with_ext(Some("my-ext-value")).unwrap()
            .with_hash(Some(vec![1, 2, 3, 4]))
            .with_app(Some("my-app")).unwrap()
            .with_dlg(Some("my-dlg")).unwrap();
        let formatted = format!("{}", s);
        println!("got: {}", s);
        let s2 = Header::from_str(&formatted).unwrap();
        assert!(s2 == s);
    }
}
