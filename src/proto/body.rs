use bytes::Bytes;
use futures::{Stream, TryStreamExt};
use std::{
    error::Error as StdError,
    pin::Pin,
    task::{Context, Poll},
};

pub struct Body {
    kind: Kind,
}

impl Body {
    pub fn empty() -> Self {
        Body {
            kind: Kind::Once(Some(Bytes::new())),
        }
    }

    pub fn wrap_stream<S, O, E>(stream: S) -> Self
    where
        S: Stream<Item = Result<O, E>> + Send + 'static,
        O: Into<Bytes> + Send + 'static,
        E: Into<Box<dyn StdError + Send + Sync>> + 'static,
    {
        let mapped =
            stream.map_ok(Into::into).map_err(Into::into);
        Body {
            kind: Kind::Stream(Wrapped(Box::pin(mapped))),
        }
    }
}

impl Stream for Body {
    type Item = Result<Bytes, Box<dyn StdError + Send + Sync>>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        match &mut self.kind {
            Kind::Stream(stream) => {
                stream.0.as_mut().poll_next(cx)
            }
            Kind::Once(opt) => Poll::Ready(opt.take().map(Ok)),
        }
    }
}

impl From<&'static str> for Body {
    fn from(slice: &'static str) -> Self {
        Body {
            kind: Kind::Once(Some(Bytes::from(slice))),
        }
    }
}

impl From<&'static [u8]> for Body {
    fn from(slice: &'static [u8]) -> Self {
        Body {
            kind: Kind::Once(Some(Bytes::from(slice))),
        }
    }
}

impl From<Bytes> for Body {
    fn from(buf: Bytes) -> Self {
        Body {
            kind: Kind::Once(Some(buf)),
        }
    }
}

impl From<String> for Body {
    fn from(buf: String) -> Self {
        Body {
            kind: Kind::Once(Some(Bytes::from(buf))),
        }
    }
}

impl From<Vec<u8>> for Body {
    fn from(buf: Vec<u8>) -> Self {
        Body {
            kind: Kind::Once(Some(Bytes::from(buf))),
        }
    }
}

enum Kind {
    Once(Option<Bytes>),
    Stream(Wrapped),
}

type BoxStrem = Pin<
    Box<
        dyn Stream<
                Item = Result<
                    Bytes,
                    Box<dyn StdError + Send + Sync>,
                >,
            > + Send,
    >,
>;

struct Wrapped(BoxStrem);

#[cfg(test)]
mod test {
    use super::Body;
    use futures::{stream, StreamExt};

    #[tokio::test]
    async fn test_once() {
        let mut body: Body = "Hello World".into();

        let res = body.next().await;

        println!("{:?}", res);
    }

    #[tokio::test]
    async fn test_stream() {
        let vec: Vec<Result<_, std::io::Error>> =
            vec![Ok("123"), Ok("456"), Ok("789")];
        let stream = stream::iter(vec);
        let mut body = Body::wrap_stream(stream);

        while let Some(s) = body.next().await {
            println!("{:?}", s);
        }

        let vec: Vec<Result<_, std::io::Error>> =
            vec![Ok("123"), Ok("456"), Ok("789")];
        let stream = stream::iter(vec);
        let mut body = Body::wrap_stream(stream);

        let h = tokio::spawn(async move {
            while let Some(s) = body.next().await {
                println!("{:?}", s);
            }
        });

        h.await.unwrap();
    }
}
