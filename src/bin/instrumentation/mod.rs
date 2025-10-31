use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::{Protocol, WithExportConfig};
use opentelemetry_sdk::trace::{RandomIdGenerator, Sampler, SdkTracer, SdkTracerProvider};
use tracing::Subscriber;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::registry::LookupSpan;

pub fn otel_layer<S>() -> OpenTelemetryLayer<S, SdkTracer>
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary)
        .build()
        .expect("to build otel otlp exporter");

    let provider = SdkTracerProvider::builder()
        .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
            1.0,
        ))))
        .with_id_generator(RandomIdGenerator::default())
        .with_batch_exporter(exporter)
        .build();

    let tracer = provider.tracer("tracing-otel-subscriber");
    tracing_opentelemetry::layer().with_tracer(tracer)
}
