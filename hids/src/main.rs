mod agent;
mod batcher;
mod collect_policy;
mod config;
mod dedup;
mod events;
mod features;
mod http_client;
mod metrics;
mod proc_cache;
mod spool;
mod string_utils;
mod tls_flow;
mod utils;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    agent::run().await
}