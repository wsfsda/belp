use bytes::{Buf, BufMut, Bytes, BytesMut};
use ring::aead::Aad;
use tokio_util::codec::{Decoder, Encoder};
use tracing::instrument;

use crate::vmess::config::ResConfig;
use crate::vmess::conn::InvalidHead;
use crate::vmess::encrypt::{
    aes_123_gcm_open, vmess_kdf_1_one_shot, AEAD_RESP_HEADER_IV,
    AEAD_RESP_HEADER_KEY, AEAD_RESP_HEADER_LEN_IV,
    AEAD_RESP_HEADER_LEN_KEY,
};
use crate::vmess::{Error, Result};

use super::Shutdown;

pub(crate) struct NoEnCodec {
    config: ResConfig,
    head: Option<Bytes>,
    is_send_head: bool,
    is_recv_head: bool,
    is_parse_head_len: bool,
}

impl NoEnCodec {
    pub(crate) fn new(header: Bytes, config: ResConfig) -> Self {
        NoEnCodec {
            config,
            head: Some(header),
            is_send_head: false,
            is_recv_head: false,
            is_parse_head_len: false,
        }
    }
}

impl NoEnCodec {
    const MAX: usize = 1 << 14;

    fn recv_head(
        &mut self,
        src: &mut BytesMut,
    ) -> Result<Option<()>> {
        if src.len() < 2 + 16 {
            return Ok(None);
        }

        let len = self.parse_head_len(src)?;

        if src.len() < 2 + 16 + len + 16 {
            return Ok(None);
        }

        self.parse_head(len, src)?;

        Ok(Some(()))
    }

    #[instrument(skip(self), err(Debug))]
    fn parse_head_len(
        &mut self,
        src: &mut BytesMut,
    ) -> Result<usize> {
        if !self.is_parse_head_len {
            let key = vmess_kdf_1_one_shot(
                &self.config.config[33..49],
                AEAD_RESP_HEADER_LEN_KEY,
            );

            let nonce = vmess_kdf_1_one_shot(
                &self.config.config[49..65],
                AEAD_RESP_HEADER_LEN_IV,
            );

            aes_123_gcm_open(
                &key.as_ref()[..16],
                &nonce.as_ref()[..12],
                Aad::empty(),
                &mut src[..18],
                0..,
            )
            .map_err(Into::<InvalidHead>::into)?;

            self.is_parse_head_len = true;
        }
        let mut buf = &src[..];
        let len = buf.get_u16() as usize;
        Ok(len)
    }

    #[instrument(skip(self, src), err(Debug))]
    fn parse_head(
        &mut self,
        len: usize,
        src: &mut BytesMut,
    ) -> Result<()> {
        let key = vmess_kdf_1_one_shot(
            &self.config.config[33..49],
            AEAD_RESP_HEADER_KEY,
        );

        let nonce = vmess_kdf_1_one_shot(
            &self.config.config[49..65],
            AEAD_RESP_HEADER_IV,
        );

        aes_123_gcm_open(
            &key.as_ref()[..16],
            &nonce.as_ref()[..12],
            Aad::empty(),
            &mut src[2 + 16..2 + 16 + len + 16],
            0..,
        )
        .map_err(Into::<InvalidHead>::into)?;

        if src[18] != self.config.config[32] {
            return Err(InvalidHead::InvalidResponseV.into());
        }

        if src[19] != 0 || src[20] != 0 {
            return Err(InvalidHead::NotSupport.into());
        }

        src.advance(2 + 16 + len + 16);
        self.is_recv_head = true;
        Ok(())
    }
}

impl Decoder for NoEnCodec {
    type Item = BytesMut;

    type Error = Error;

    fn decode(
        &mut self,
        src: &mut BytesMut,
    ) -> Result<Option<Self::Item>> {
        if !self.is_recv_head && (self.recv_head(src)?).is_none()
        {
            return Ok(None);
        }

        let mut buf = src.as_ref();

        if buf.len() < 2 {
            return Ok(None);
        }

        let len = buf.get_u16() as usize;
        if buf.len() < len {
            return Ok(None);
        }

        src.advance(2);

        let item = src.split_to(len);

        Ok(Some(item))
    }
}

impl Encoder<BytesMut> for NoEnCodec {
    type Error = Error;

    fn encode(
        &mut self,
        item: BytesMut,
        dst: &mut BytesMut,
    ) -> Result<()> {
        if !self.is_send_head {
            let head = self.head.take().expect("没有加密的头");
            dst.put(head);
            self.is_send_head = true;
        }

        let mut buf = item;

        while buf.has_remaining() {
            let mut len = buf.remaining();
            if len > NoEnCodec::MAX {
                len = NoEnCodec::MAX
            }

            dst.put_u16(len as u16);
            dst.put(&buf[..len]);

            buf.advance(len);
        }

        Ok(())
    }
}

impl Encoder<Shutdown> for NoEnCodec {
    type Error = Error;

    fn encode(
        &mut self,
        _item: Shutdown,
        dst: &mut BytesMut,
    ) -> Result<()> {
        dst.put_u16(0);

        Ok(())
    }
}
