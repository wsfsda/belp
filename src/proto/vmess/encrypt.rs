use std::ops::RangeFrom;

use bytes::BytesMut;
use once_cell::sync::Lazy;
use ring::aead::{
    Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM,
};
use ring::hmac::{Context, Key, Tag, HMAC_SHA256};
use ring::rand::{SecureRandom, SystemRandom};

pub static RAND: Lazy<SystemRandom> = Lazy::new(|| {
    let rand = SystemRandom::new();
    let mut x = [0];
    rand.fill(&mut x).unwrap();
    rand
});

pub static VMESS_AEAD_KDF: &[u8] = b"VMess AEAD KDF";
pub static AES_AUTH_ID_ENCRYPTION: &[u8] =
    b"AES Auth ID Encryption";
pub static VMESS_HEADER_AEAD_KEY_LENGTH: &[u8] =
    b"VMess Header AEAD Key_Length";
pub static VMESS_HEADER_AEAD_NONCE_LENGTH: &[u8] =
    b"VMess Header AEAD Nonce_Length";
pub static VMESS_HEADER_AEAD_KEY: &[u8] =
    b"VMess Header AEAD Key";
pub static VMESS_HEADER_AEAD_NONCE: &[u8] =
    b"VMess Header AEAD Nonce";
pub static AEAD_RESP_HEADER_LEN_KEY: &[u8] =
    b"AEAD Resp Header Len Key";
pub static AEAD_RESP_HEADER_LEN_IV: &[u8] =
    b"AEAD Resp Header Len IV";
pub static AEAD_RESP_HEADER_KEY: &[u8] = b"AEAD Resp Header Key";
pub static AEAD_RESP_HEADER_IV: &[u8] = b"AEAD Resp Header IV";

#[derive(Clone)]
pub struct VmessKdf1 {
    okey: [u8; Self::BLOCK_LEN],
    hasher: Context,
    hasher_outer: Context,
}

impl VmessKdf1 {
    pub const BLOCK_LEN: usize = 64;
    pub const TAG_LEN: usize = 32;
    const IPAD: u8 = 0x36;
    const OPAD: u8 = 0x5c;

    pub fn new(mut hasher: Context, data: &[u8]) -> Self {
        let mut ikey = [0u8; Self::BLOCK_LEN];
        let mut okey = [0u8; Self::BLOCK_LEN];
        let hasher_outer = hasher.clone();

        if data.len() > Self::BLOCK_LEN {
            let mut hh = hasher.clone();
            hh.update(data);
            let tag = hh.sign();
            let hkey = tag.as_ref();
            ikey[..Self::TAG_LEN]
                .copy_from_slice(&hkey[..Self::TAG_LEN]);
            okey[..Self::TAG_LEN]
                .copy_from_slice(&hkey[..Self::TAG_LEN]);
        }

        ikey[..data.len()].copy_from_slice(data);
        okey[..data.len()].copy_from_slice(data);

        for idx in 0..Self::BLOCK_LEN {
            ikey[idx] ^= Self::IPAD;
            okey[idx] ^= Self::OPAD;
        }
        hasher.update(&ikey);
        Self {
            okey,
            hasher,
            hasher_outer,
        }
    }

    pub fn update(&mut self, m: &[u8]) {
        self.hasher.update(m);
    }

    pub fn sign(mut self) -> Tag {
        let tag = self.hasher.sign();
        let h1 = tag.as_ref();
        self.hasher_outer.update(&self.okey);
        self.hasher_outer.update(h1);

        self.hasher_outer.sign()
    }
}

macro_rules! impl_hmac_with_hasher {
    ($name:tt, $hasher:tt) => {
        #[derive(Clone)]
        pub struct $name {
            okey: [u8; Self::BLOCK_LEN],
            hasher: $hasher,
            hasher_outer: $hasher,
        }

        impl $name {
            pub const BLOCK_LEN: usize = 64;
            pub const TAG_LEN: usize = 32;
            const IPAD: u8 = 0x36;
            const OPAD: u8 = 0x5c;

            pub fn new(
                mut hasher: $hasher,
                data: &[u8],
            ) -> Self {
                let mut ikey = [0u8; Self::BLOCK_LEN];
                let mut okey = [0u8; Self::BLOCK_LEN];
                let hasher_outer = hasher.clone();

                if data.len() > Self::BLOCK_LEN {
                    let mut hh = hasher.clone();
                    hh.update(data);
                    let tag = hh.sign();
                    let hkey = tag.as_ref();
                    ikey[..Self::TAG_LEN]
                        .copy_from_slice(&hkey[..Self::TAG_LEN]);
                    okey[..Self::TAG_LEN]
                        .copy_from_slice(&hkey[..Self::TAG_LEN]);
                }

                ikey[..data.len()].copy_from_slice(data);
                okey[..data.len()].copy_from_slice(data);

                for idx in 0..Self::BLOCK_LEN {
                    ikey[idx] ^= Self::IPAD;
                    okey[idx] ^= Self::OPAD;
                }
                hasher.update(&ikey);
                Self {
                    okey,
                    hasher,
                    hasher_outer,
                }
            }

            pub fn update(&mut self, m: &[u8]) {
                self.hasher.update(m);
            }

            pub fn sign(mut self) -> Tag {
                let tag = self.hasher.sign();
                let h1 = tag.as_ref();
                self.hasher_outer.update(&self.okey);
                self.hasher_outer.update(h1);

                self.hasher_outer.sign()
            }
        }
    };
}

impl_hmac_with_hasher!(VmessKdf2, VmessKdf1);
impl_hmac_with_hasher!(VmessKdf3, VmessKdf2);

fn get_vmess_kdf_1(data1: &[u8]) -> VmessKdf1 {
    let key = Key::new(HMAC_SHA256, VMESS_AEAD_KDF);
    let ctx = Context::with_key(&key);

    VmessKdf1::new(ctx, data1)
}

pub fn vmess_kdf_1_one_shot(
    cmd_key: &[u8],
    data1: &[u8],
) -> Tag {
    let mut h = get_vmess_kdf_1(data1);
    h.update(cmd_key);
    h.sign()
}

fn get_vmess_kdf_2(key1: &[u8], key2: &[u8]) -> VmessKdf2 {
    VmessKdf2::new(get_vmess_kdf_1(key1), key2)
}

fn get_vmess_kdf_3(
    key1: &[u8],
    key2: &[u8],
    key3: &[u8],
) -> VmessKdf3 {
    VmessKdf3::new(get_vmess_kdf_2(key1, key2), key3)
}

pub fn vmess_kdf_3_one_shot(
    cmd_key: &[u8],
    data1: &[u8],
    data2: &[u8],
    data3: &[u8],
) -> Tag {
    let mut h = get_vmess_kdf_3(data1, data2, data3);
    h.update(cmd_key);
    h.sign()
}

pub fn aes_123_gcm_seal<T: AsRef<[u8]>>(
    key: &[u8],
    nonce: &[u8],
    aad: Aad<T>,
    data: &mut BytesMut,
) {
    let key = UnboundKey::new(&AES_128_GCM, key).unwrap();
    let ctx = LessSafeKey::new(key);
    let nonce = Nonce::try_assume_unique_for_key(nonce).unwrap();
    ctx.seal_in_place_append_tag(nonce, Aad::from(aad), data)
        .unwrap();
}

pub fn aes_123_gcm_open<T: AsRef<[u8]>>(
    key: &[u8],
    nonce: &[u8],
    aad: Aad<T>,
    data_and_tag: &mut [u8],
    data_and_tag_len: RangeFrom<usize>,
) -> Result<(), ring::error::Unspecified> {
    let key = UnboundKey::new(&AES_128_GCM, key).unwrap();
    let ctx = LessSafeKey::new(key);
    let nonce = Nonce::try_assume_unique_for_key(nonce).unwrap();
    ctx.open_within(nonce, aad, data_and_tag, data_and_tag_len)?;

    Ok(())
}

pub struct Fnv1a(u32);

const INIT: u32 = 0x811c9dc5u32;

impl Fnv1a {
    pub fn new() -> Self {
        Fnv1a(INIT)
    }

    pub fn update(&mut self, data: impl AsRef<[u8]>) {
        let mut hash = self.0;

        for byte in data.as_ref().iter() {
            hash ^= *byte as u32;
            hash = hash.wrapping_mul(0x01000193);
        }

        self.0 = hash
    }

    pub fn finalize(self) -> u32 {
        self.0
    }
}

macro_rules! fnv1a {
  ($($x:expr),+) => {
      {
      use $crate::proto::vmess::encrypt::Fnv1a;

      let mut fnvla = Fnv1a::new();
      $(
        fnvla.update($x);
      )+
      fnvla.finalize()
    }
  };
}

pub(crate) use fnv1a;

#[cfg(test)]
mod test {
    use bytes::BytesMut;
    use ring::aead::Aad;

    use crate::proto::vmess::encrypt::{
        aes_123_gcm_open, vmess_kdf_1_one_shot,
        vmess_kdf_3_one_shot, AES_AUTH_ID_ENCRYPTION,
        VMESS_HEADER_AEAD_KEY_LENGTH,
    };

    use super::aes_123_gcm_seal;

    #[test]
    fn kdf_1() {
        let cmd_key = b"1111111111111111";
        let res = vmess_kdf_1_one_shot(
            cmd_key,
            AES_AUTH_ID_ENCRYPTION,
        );
        println!("{:?}", &res);
    }

    #[test]
    fn kdf3() {
        let cmd_key = b"1111111111111111";
        let res = vmess_kdf_3_one_shot(
            cmd_key,
            VMESS_HEADER_AEAD_KEY_LENGTH,
            b"12345678",
            b"12345678",
        );
        println!("{:?}", &res);
    }

    #[test]
    fn aes_123_gcm_seal_test() {
        let key = b"1111111111111111";
        let nonce = b"111111111111";
        let mut buf = BytesMut::with_capacity(1024);
        buf.extend_from_slice(b"Hello Wold");
        println!("{:x?}", &buf[..]);

        aes_123_gcm_seal(key, nonce, Aad::empty(), &mut buf);
        println!("{:x?}", &buf[..]);

        aes_123_gcm_open(
            key,
            nonce,
            Aad::empty(),
            &mut buf,
            0..,
        )
        .unwrap();

        println!("{:x?}", &buf[..]);
    }
}
