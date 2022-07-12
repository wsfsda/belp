pub mod proto;

macro_rules! ready {
    ($f:expr) => {
        match $f {
            Poll::Ready(t) => t,
            Poll::Pending => return Poll::Pending,
        }
    };
}

pub(crate) use ready;
