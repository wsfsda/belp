use bytes::Bytes;

use super::Encryption;

pub struct ResponseConfig {
    // req_key ..16
    // req_iv 16..32
    // v 32..32
    // res_key 33..49
    // res_iv 49..65
    pub config: Bytes,
    pub encrytin: Encryption,
}
