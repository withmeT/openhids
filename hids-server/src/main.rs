#[tokio::main]
async fn main() -> anyhow::Result<()> {
    hids_server::run().await
}
