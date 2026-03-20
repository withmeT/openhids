mod agent;
mod batcher;
mod events;
mod http_client;
mod spool;
mod utils;

// feature placeholders (future development)
mod features;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    agent::run().await
}