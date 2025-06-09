//! Example of how to create an HTTP/3 RPC server using Reth components
//!
//! This example demonstrates:
//! 1. How to create a standalone HTTP/3 RPC server with Reth APIs
//! 2. How to use custom certificates for HTTP/3
//! 3. How to test HTTP/3 connectivity with a client
//!
//! ## Usage
//!
//! ### With self-signed certificates (development):
//! ```sh
//! cargo run -p example-rpc-http3 -- --http3 --http3-cert-mode self-signed --test-client
//! ```
//!
//! ### With custom certificates (production):
//! ```sh
//! # First generate certificates
//! openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"
//!
//! # Then run with custom certificates
//! cargo run -p example-rpc-http3 -- --http3 --http3-cert-mode custom --http3-cert-path cert.pem --http3-key-path key.pem --test-client
//! ```
//!
//! ### Test with HTTP/3 client manually:
//! ```sh
//! # This will create an HTTP/3 server on port 8545 (by default)
//! curl --http3 -X POST -H "Content-Type: application/json" \
//!   -d '{"jsonrpc":"2.0","method":"web3_clientVersion","params":[],"id":1}' \
//!   https://localhost:8545
//! ```

#![warn(unused_crate_dependencies)]

use clap::{Parser, ValueEnum};
use jsonrpsee::{
    core::client::ClientT,
    http_client::{CertificateVerificationMode, HttpClientBuilder},
};
use reth_ethereum::{
    cli::{chainspec::EthereumChainSpecParser, interface::Cli},
    node::EthereumNode,
};
use reth_rpc_builder::{CertificateConfig, Http3Config};
use std::{path::PathBuf, time::Duration};
use tracing_subscriber::util::SubscriberInitExt;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::FmtSubscriber::builder().with_env_filter(filter).finish().try_init()?;

    let args = RethCliHttp3::parse();

    if args.http3 {
        run_http3_rpc_server(args).await
    } else {
        tracing::info!(
            "Starting standard Reth node. Use --http3 to enable HTTP/3 RPC server example."
        );
        run_standard_reth_node(args).await
    }
}

/// Run a standalone HTTP/3 RPC server with Reth APIs
async fn run_http3_rpc_server(args: RethCliHttp3) -> eyre::Result<()> {
    use jsonrpsee::{
        server::{RpcModule, ServerBuilder, ServerConfig},
        types::ErrorObjectOwned,
    };

    tracing::info!("Starting HTTP/3 RPC server example");

    let cert_config = match args.http3_cert_mode {
        CertMode::SelfSigned => {
            tracing::info!("Using self-signed certificate for HTTP/3");
            CertificateConfig::SelfSigned { dns_name: "localhost".to_string() }
        }
        CertMode::Custom => {
            let cert_path = args.http3_cert_path.as_ref().ok_or_else(|| {
                eyre::eyre!("--http3-cert-path required when using custom certificates")
            })?;
            let key_path = args.http3_key_path.as_ref().ok_or_else(|| {
                eyre::eyre!("--http3-key-path required when using custom certificates")
            })?;

            tracing::info!(
                "Loading custom certificates from {} and {}",
                cert_path.display(),
                key_path.display()
            );

            let cert_chain = std::fs::read(cert_path)
                .map_err(|e| eyre::eyre!("Failed to read certificate file: {}", e))?;
            let private_key = std::fs::read(key_path)
                .map_err(|e| eyre::eyre!("Failed to read private key file: {}", e))?;

            CertificateConfig::Custom { cert_chain, private_key }
        }
    };

    let http3_config = Http3Config {
        max_connections: args.http3_max_connections,
        max_concurrent_requests_per_connection: args.http3_max_concurrent_requests,
        max_idle_timeout: Duration::from_secs(args.http3_max_idle_timeout),
        enable_0rtt: args.http3_enable_0rtt,
        enable_bbr: args.http3_enable_bbr,
        cert_config,
        ..Default::default()
    };

    let config = ServerConfig::builder().enable_http3().with_http3_config(http3_config).build();

    let addr = "127.0.0.1:8545".parse::<std::net::SocketAddr>()?;
    let server = ServerBuilder::default().set_config(config).build(addr).await?;

    let mut module = RpcModule::new(());

    // Add some basic RPC methods
    module.register_method(
        "web3_clientVersion",
        |_, _, _| -> Result<String, ErrorObjectOwned> {
            Ok("reth-http3-example/1.0.0".to_string())
        },
    )?;

    module.register_method("net_version", |_, _, _| -> Result<String, ErrorObjectOwned> {
        Ok("1".to_string()) // Mainnet
    })?;

    module.register_method("eth_chainId", |_, _, _| -> Result<String, ErrorObjectOwned> {
        Ok("0x1".to_string()) // Mainnet chain ID
    })?;

    module.register_method("eth_blockNumber", |_, _, _| -> Result<String, ErrorObjectOwned> {
        Ok("0x123456".to_string()) // Mock block number
    })?;

    module.register_method("ping", |_, _, _| -> Result<String, ErrorObjectOwned> {
        Ok("pong".to_string())
    })?;

    module.register_method("echo", |params, _, _| -> Result<String, ErrorObjectOwned> {
        let text: String = params.one()?;
        Ok(format!("Echo: {text}"))
    })?;

    let server_addr = server.local_addr()?;
    tracing::info!("HTTP/3 RPC server listening on https://{}", server_addr);
    tracing::info!("Configuration:");
    tracing::info!("  Max connections: {}", args.http3_max_connections);
    tracing::info!(
        "  Max concurrent requests per connection: {}",
        args.http3_max_concurrent_requests
    );
    tracing::info!("  Max idle timeout: {}s", args.http3_max_idle_timeout);
    tracing::info!("  0-RTT enabled: {}", args.http3_enable_0rtt);
    tracing::info!("  BBR enabled: {}", args.http3_enable_bbr);

    let handle = server.start(module);

    // If test_client is enabled, test the connection
    if args.test_client {
        let url = format!("https://{server_addr}");
        tracing::info!("Testing HTTP/3 client connection to {}", url);

        tokio::spawn(async move {
            // Give server time to start
            tokio::time::sleep(Duration::from_secs(2)).await;

            if let Err(e) = test_http3_client(&url).await {
                tracing::error!("HTTP/3 client test failed: {}", e);
            } else {
                tracing::info!("✅ HTTP/3 client test passed");
            }
        });
    }

    tracing::info!("Server running. Press Ctrl+C to stop.");

    // Wait for shutdown signal
    tokio::signal::ctrl_c().await?;

    tracing::info!("Shutting down HTTP/3 server...");
    handle.stop().ok();

    Ok(())
}

/// Run standard Reth node (fallback when HTTP/3 is not enabled)
async fn run_standard_reth_node(_args: RethCliHttp3) -> eyre::Result<()> {
    Cli::<EthereumChainSpecParser, RethCliHttp3>::parse().run(|builder, _args| async move {
        let handle = builder.node(EthereumNode::default()).launch().await?;
        handle.wait_for_node_exit().await
    })
}

/// Test HTTP/3 client connectivity
async fn test_http3_client(url: &str) -> eyre::Result<()> {
    let client = HttpClientBuilder::default()
        .enable_http3()
        .with_http3_certificate_verification(CertificateVerificationMode::AcceptSelfSigned)
        .build(url)
        .await?;

    // Test ping
    let response: String = client.request("ping", reth_rpc::rpc_params![]).await?;
    tracing::info!("Ping response: {}", response);
    assert_eq!(response, "pong");

    // Test echo
    let test_message = "Hello HTTP/3!";
    let response: String = client.request("echo", reth_rpc::rpc_params![test_message]).await?;
    tracing::info!("Echo response: {}", response);
    assert_eq!(response, format!("Echo: {test_message}"));

    // Test basic RPC calls
    let result: serde_json::Value =
        client.request("eth_blockNumber", reth_rpc::rpc_params![]).await?;
    tracing::info!("eth_blockNumber response: {}", result);

    let result: serde_json::Value = client.request("eth_chainId", reth_rpc::rpc_params![]).await?;
    tracing::info!("eth_chainId response: {}", result);

    let result: serde_json::Value =
        client.request("web3_clientVersion", reth_rpc::rpc_params![]).await?;
    tracing::info!("web3_clientVersion response: {}", result);

    Ok(())
}

/// Certificate mode for HTTP/3
#[derive(Debug, Clone, Copy, ValueEnum)]
enum CertMode {
    /// Use self-signed certificate (development only)
    SelfSigned,
    /// Use custom certificate from files
    Custom,
}

impl Default for CertMode {
    fn default() -> Self {
        Self::SelfSigned
    }
}

/// Our custom CLI args extension that adds HTTP/3 configuration to reth CLI.
#[derive(Debug, Clone, Default, Parser)]
#[command(name = "reth-http3-example")]
#[command(about = "Reth HTTP/3 RPC server example")]
struct RethCliHttp3 {
    /// Enable HTTP/3 for RPC server
    #[arg(long)]
    pub http3: bool,

    /// Certificate mode for HTTP/3
    #[arg(long, value_enum, default_value = "self-signed")]
    pub http3_cert_mode: CertMode,

    /// Path to certificate file (required for custom cert mode)
    #[arg(long)]
    pub http3_cert_path: Option<PathBuf>,

    /// Path to private key file (required for custom cert mode)
    #[arg(long)]
    pub http3_key_path: Option<PathBuf>,

    /// Maximum number of HTTP/3 connections
    #[arg(long, default_value = "1000")]
    pub http3_max_connections: usize,

    /// Maximum concurrent requests per HTTP/3 connection
    #[arg(long, default_value = "100")]
    pub http3_max_concurrent_requests: usize,

    /// Maximum idle timeout for HTTP/3 connections (seconds)
    #[arg(long, default_value = "60")]
    pub http3_max_idle_timeout: u64,

    /// Enable 0-RTT for HTTP/3
    #[arg(long)]
    pub http3_enable_0rtt: bool,

    /// Enable BBR congestion control for HTTP/3
    #[arg(long)]
    pub http3_enable_bbr: bool,

    /// Test HTTP/3 client connectivity after server start
    #[arg(long)]
    pub test_client: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use jsonrpsee::server::ServerBuilder;
    #[allow(unused_imports)]
    use std::net::SocketAddr;

    /// Test that we can create HTTP/3 configuration
    #[test]
    fn test_http3_config_creation() {
        let config = Http3Config {
            max_connections: 100,
            max_concurrent_requests_per_connection: 10,
            max_idle_timeout: Duration::from_secs(30),
            enable_0rtt: true,
            cert_config: CertificateConfig::SelfSigned { dns_name: "localhost".to_string() },
            ..Default::default()
        };

        assert_eq!(config.max_connections, 100);
        assert_eq!(config.max_concurrent_requests_per_connection, 10);
        assert_eq!(config.max_idle_timeout, Duration::from_secs(30));
        assert!(config.enable_0rtt);
    }

    /// Test that custom certificate config works
    #[test]
    fn test_custom_cert_config() {
        let cert_chain = b"-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----".to_vec();
        let private_key = b"-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----".to_vec();

        let config = Http3Config {
            cert_config: CertificateConfig::Custom {
                cert_chain: cert_chain.clone(),
                private_key: private_key.clone(),
            },
            ..Default::default()
        };

        if let CertificateConfig::Custom { cert_chain: c, private_key: k } = config.cert_config {
            assert_eq!(c, cert_chain);
            assert_eq!(k, private_key);
        } else {
            panic!("Expected Custom certificate config");
        }
    }

    /// Test server creation with HTTP/3 (minimal test without actual networking)
    #[tokio::test]
    async fn test_http3_server_creation() {
        // This test just verifies we can create the configuration without panicking
        let http3_config = Http3Config {
            max_connections: 10,
            max_concurrent_requests_per_connection: 5,
            max_idle_timeout: Duration::from_secs(10),
            cert_config: CertificateConfig::SelfSigned { dns_name: "localhost".to_string() },
            ..Default::default()
        };

        // Just test that the config is valid
        assert_eq!(http3_config.max_connections, 10);
    }
}
