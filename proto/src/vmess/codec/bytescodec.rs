use bytes::{BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use crate::vmess::Error;

pub(crate) struct BytesCodec;

impl BytesCodec {
    fn new() -> Self {
        BytesCodec
    }
}

impl Default for BytesCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder for BytesCodec {
    type Item = BytesMut;

    type Error = Error;

    fn decode(
        &mut self,
        buf: &mut bytes::BytesMut,
    ) -> Result<Option<Self::Item>, Self::Error> {
        if !buf.is_empty() {
            let len = buf.len();
            Ok(Some(buf.split_to(len)))
        } else {
            Ok(None)
        }
    }
}

impl Encoder<BytesMut> for BytesCodec {
    type Error = Error;

    fn encode(
        &mut self,
        data: BytesMut,
        buf: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        buf.put(data);
        Ok(())
    }
}
