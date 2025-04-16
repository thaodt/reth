use alloy_provider::BoxedFut;
use jsonrpsee::{server::middleware::rpc::RpcServiceT, types::Request, MethodResponse, RpcModule};
use reth_metrics::{
    metrics::{Counter, Histogram},
    Metrics,
};
use std::{
    collections::HashMap,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Instant,
};
use tower::Layer;
use tracing::{span, Instrument, Span};

#[derive(Default, Debug, Clone)]
pub(crate) struct Otlp {
    endpoint: Endpoint,
}

impl Otlp {
    pub(crate) fn new(module: &RpcModule<()>, endpoint: Endpoint) -> Self {
        Self { endpoint }
    }

    pub(crate) fn http(module: &RpcModule<()>, socket: SocketAddr) -> Self {
        Self::new(module, Endpoint::Http(socket))
    }

    pub(crate) fn ws(module: &RpcModule<()>, socket: SocketAddr) -> Self {
        Self::new(module, Endpoint::WebSocket(socket))
    }

    pub(crate) fn ipc(module: &RpcModule<()>, path: String) -> Self {
        Self::new(module, Endpoint::Ipc(path))
    }
}

impl<S> Layer<S> for Otlp {
    type Service = OtlpService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        OtlpService::new(inner, self.clone())
    }
}

pub(crate) enum Endpoint {
    Socket(SocketAddr),
    Path(String),
}

impl Endpoint {
    fn server_address(&self) -> &str {
        match self {
            Endpoint::Socket(addr) => addr.ip().to_string().as_str(),
            Endpoint::Path(path) => path.as_str(),
        }
    }

    fn server_port(&self) -> Option<u16> {
        match self {
            Endpoint::Socket(addr) => Some(addr.port()),
            Endpoint::Path(_) => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct OtlpService<S> {
    endpoint: Endpoint,
    inner: S,
}

impl<S> OtlpService<S> {
    pub(crate) fn new(service: S, endpoint: Endpoint) -> Self {
        Self { inner: service, endpoint }
    }
}

impl<'a, S> RpcServiceT<'a> for OtlpService<S>
where
    S: RpcServiceT<'a> + Send + Sync + Clone + 'static,
{
    type Future = BoxedFut<<S::Future as Future>::Output>;

    fn call(&self, req: Request<'a>) -> Self::Future {
        let method = req.method.as_ref();
        // todo: trace context propagation?
        let span = span!(
            Level::INFO,
            "request",
            otel.kind = ?SpanKind::Server,
            otel.name = format!("reth/{}", method),
            rpc.jsonrpc.version = "2.0",
            rpc.system = "jsonrpc",
            rpc.jsonrpc.request_id = %req.id(),
            rpc.method = method,
            server.address = %self.endpoint.server_address(),
            server.port = self.endpoint.port().unwrap_or(tracing::field::Empty),
        );

        async move {
            // the span handle is cloned here so we can record more fields later
            let resp = self.inner.call(req).await.instrument(span.clone());
            if let Some(error_code) = resp.as_error_code() {
                span.record("rpc.jsonrpc.error_code", error_code);
            }
            response
        }
        .boxed()
    }
}
