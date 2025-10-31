mod instrumentation;

use reqwest::Url;
use tracing_subscriber::layer::SubscriberExt;

#[derive(Debug, Clone, clap::Args)]
pub struct GlobalArgs {
    /// Upstream PLC server
    #[arg(short, long, global = true, env = "ALLEGEDLY_UPSTREAM")]
    #[clap(default_value = "https://plc.directory")]
    pub upstream: Url,
    /// Self-rate-limit upstream request interval
    ///
    /// plc.directory's rate limiting is 500 requests per 5 mins (600ms)
    #[arg(long, global = true, env = "ALLEGEDLY_UPSTREAM_THROTTLE_MS")]
    #[clap(default_value = "600")]
    pub upstream_throttle_ms: u64,
}

#[derive(Debug, Default, Clone, clap::Args)]
pub struct InstrumentationArgs {
    /// Export traces to an OTLP collector
    ///
    /// Configure the colletctor via standard env vars:
    /// - `OTEL_EXPORTER_OTLP_ENDPOINT` eg "https://api.honeycomb.io/"
    /// - `OTEL_EXPORTER_OTLP_HEADERS` eg "x-honeycomb-team=supersecret"
    /// - `OTEL_SERVICE_NAME` eg "my-app"
    #[arg(long, action, global = true, env = "ALLEGEDLY_ENABLE_OTEL")]
    pub enable_opentelemetry: bool,
}

pub fn bin_init(enable_otlp: bool) {
    let filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
        .from_env_lossy();

    let stderr_log = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .pretty();

    let otel = if enable_otlp {
        Some(instrumentation::otel_layer())
    } else {
        None
    };

    let subscriber = tracing_subscriber::Registry::default()
        .with(filter)
        .with(stderr_log)
        .with(otel);

    tracing::subscriber::set_global_default(subscriber).expect("to set global tracing subscriber");
}

#[allow(dead_code)]
fn main() {
    panic!("this is not actually a module")
}
