use bytes::BytesMut;
use tokio_util::codec::{Decoder, Encoder};

use crate::vmess::Error;

use super::Shutdown;

pub(crate) struct Aes128GcmCodec;

impl Decoder for Aes128GcmCodec {
    type Item = BytesMut;

    type Error = Error;

    fn decode(
        &mut self,
        _src: &mut BytesMut,
    ) -> Result<Option<Self::Item>, Self::Error> {
        todo!()
    }
}

impl Encoder<BytesMut> for Aes128GcmCodec {
    type Error = Error;

    fn encode(
        &mut self,
        _item: BytesMut,
        _dst: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        todo!()
    }
}

impl Encoder<Shutdown> for Aes128GcmCodec {
    type Error = Error;

    fn encode(
        &mut self,
        _item: Shutdown,
        _dst: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        todo!()
    }
}
