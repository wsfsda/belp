mod context;
mod error;

#[tokio::main]
async fn main() {
    let context = context::Context::new().unwrap();

    let res = context.run().await;

    println!("{:?}", res);
}
