use ring::hmac;
use std::io;
use rustc_serialize::base64;
use rustc_serialize::base64::ToBase64;
use std::io::Write;
use time;

pub fn make_mac(key: &hmac::SigningKey, ts: time::Timespec, nonce: &str, method: &str, path: &str,
                host: &str, port: u16, hash: Option<&Vec<u8>>, ext: Option<&str>) ->
                Result<Vec<u8>, String>

{
    let mut buffer: Vec<u8> = vec![];
    let fill = |buffer: &mut Vec<u8>| {
        try!(write!(buffer, "hawk.1.header\n"));
        try!(write!(buffer, "{}\n", ts.sec));
        try!(write!(buffer, "{}\n", nonce));
        try!(write!(buffer, "{}\n", method));
        try!(write!(buffer, "{}\n", path));
        try!(write!(buffer, "{}\n", host));
        try!(write!(buffer, "{}\n", port));

        if let Some(ref h) = hash {
            try!(write!(buffer,
                        "{}\n",
                        h.to_base64(base64::Config {
                            char_set: base64::CharacterSet::Standard,
                            newline: base64::Newline::LF,
                            pad: true,
                            line_length: None,
                        })));
        } else {
            try!(write!(buffer, "\n"));
        }

        match ext {
            Some(ref e) => try!(write!(buffer, "{}\n", e)),
            None => try!(write!(buffer, "\n")),
        };
        Ok(())
    };
    try!(fill(&mut buffer).map_err(|err: io::Error| err.to_string()));

    let digest = hmac::sign(key, buffer.as_ref());

    let mut mac = vec![0; key.digest_algorithm().output_len];
    mac.clone_from_slice(digest.as_ref());
    return Ok(mac);
}

#[cfg(test)]
mod test {
    use super::make_mac;
    use time::Timespec;
    use credentials::Credentials;
    use ring::digest;

    fn key() -> Vec<u8> {
        vec![11u8, 19, 228, 209, 79, 189, 200, 59, 166, 47, 86, 254, 235, 184, 120, 197, 75, 152,
             201, 79, 115, 61, 111, 242, 219, 187, 173, 14, 227, 108, 60, 232]
    }

    #[test]
    fn test_make_mac() {
        let key = key();
        let credentials = Credentials::new("req-id", key, &digest::SHA256);
        let mac = make_mac(&credentials.key, Timespec::new(1000, 100), "nonny", "POST", "/v1/api", "mysite.com", 443, None, None).unwrap();
        println!("got {:?}", mac);
        assert!(mac ==
                vec![192, 227, 235, 121, 157, 185, 197, 79, 189, 214, 235, 139, 9, 232, 99, 55, 67,
                     30, 68, 0, 150, 187, 192, 238, 21, 200, 209, 107, 245, 159, 243, 178]);
    }

    #[test]
    fn test_make_mac_hash() {
        let key = key();
        let credentials = Credentials::new("req-id", key, &digest::SHA256);
        let hash = vec![1, 2, 3, 4, 5];
        let mac = make_mac(&credentials.key, Timespec::new(1000, 100), "nonny", "POST", "/v1/api", "mysite.com", 443, Some(&hash), None).unwrap();
        println!("got {:?}", mac);
        assert!(mac ==
                vec![61, 128, 208, 253, 88, 135, 190, 196, 1, 69, 153, 193, 124, 4, 195, 87, 38,
                     96, 181, 34, 65, 234, 58, 157, 175, 175, 145, 151, 61, 0, 57, 5]);
    }

    #[test]
    fn test_make_mac_ext() {
        let key = key();
        let credentials = Credentials::new("req-id", key, &digest::SHA256);
        let ext = "ext-data".to_string();
        let mac = make_mac(&credentials.key, Timespec::new(1000, 100), "nonny", "POST", "/v1/api", "mysite.com", 443, None, Some(&ext)).unwrap();
        println!("got {:?}", mac);
        assert!(mac ==
                vec![187, 104, 238, 100, 168, 112, 37, 68, 187, 141, 168, 155, 177, 193, 113, 0,
                     50, 105, 127, 36, 24, 117, 200, 251, 138, 199, 108, 14, 105, 123, 234, 119]);
    }
}