use opentelemetry::metrics::Meter;
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_otlp::LogExporter;
use opentelemetry_otlp::MetricExporter;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::logs::SdkLoggerProvider;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use sentry::ClientInitGuard;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

/// RAII guard that flushes logs, metrics, and sentry on drop.
pub struct TelemetryGuard {
    _sentry_guard: Option<ClientInitGuard>,
    _writer_guard: Option<tracing_appender::non_blocking::WorkerGuard>,
    _log_provider: Option<SdkLoggerProvider>,
    _meter_provider: Option<SdkMeterProvider>,
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        // Flush metrics before process exit
        if let Some(ref meter_provider) = self._meter_provider
            && let Err(e) = meter_provider.shutdown()
        {
            eprintln!("Failed to shutdown meter provider: {e}");
        }
        // Flush logs before process exit
        if let Some(ref log_provider) = self._log_provider
            && let Err(e) = log_provider.shutdown()
        {
            eprintln!("Failed to shutdown log provider: {e}");
        }
        // Sentry guard and writer guard flush via their own Drop impls
    }
}

/// Initialize tracing with Sentry + OTEL log/metrics bridging.
///
/// - Sentry is always initialised (reads `SENTRY_DSN`).
/// - OTEL log bridge and meter provider are always initialised,
///   exporting to `OTEL_EXPORTER_OTLP_ENDPOINT` (default `http://localhost:4317`).
/// - Returns a [`TelemetryGuard`] that flushes everything on drop.
pub fn init_telemetry(service_name: &str, default_filter: Option<&str>) -> TelemetryGuard {
    let default_filter = default_filter.unwrap_or("info");
    let default_env_filter = format!(
        "{},h2=off,tonic=off,hyper=off,reqwest=off,rustls=off,opentelemetry=off,opentelemetry_sdk=off,opentelemetry_otlp=off",
        default_filter
    );
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_env_filter));

    // Sentry
    let sentry_dsn = std::env::var("SENTRY_DSN").unwrap_or_default();
    let sentry_guard = sentry::init((
        sentry_dsn,
        sentry::ClientOptions {
            release: sentry::release_name!(),
            traces_sample_rate: 1.0,
            debug: true,
            ..Default::default()
        },
    ));

    let (non_blocking_writer, writer_guard) = tracing_appender::non_blocking(std::io::stdout());

    // OTEL resource
    let resource = Resource::builder()
        .with_service_name(service_name.to_string())
        .build();

    let endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
        .unwrap_or_else(|_| "http://localhost:4317".to_string());

    // OTEL log provider + tracing bridge
    let mut otel_log_layer = None;
    let mut log_provider_out = None;

    if let Ok(log_exporter) = LogExporter::builder()
        .with_tonic()
        .with_endpoint(&endpoint)
        .build()
    {
        let log_provider = SdkLoggerProvider::builder()
            .with_resource(resource.clone())
            .with_batch_exporter(log_exporter)
            .build();
        otel_log_layer = Some(OpenTelemetryTracingBridge::new(&log_provider));
        log_provider_out = Some(log_provider);
    }

    // OTEL meter provider
    let mut meter_provider_out = None;

    if let Ok(metric_exporter) = MetricExporter::builder()
        .with_tonic()
        .with_endpoint(&endpoint)
        .build()
    {
        let meter_provider = SdkMeterProvider::builder()
            .with_resource(resource)
            .with_periodic_exporter(metric_exporter)
            .build();
        opentelemetry::global::set_meter_provider(meter_provider.clone());
        meter_provider_out = Some(meter_provider);
    }

    // Assemble tracing subscriber
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_writer(non_blocking_writer))
        .with(sentry_tracing::layer())
        .with(otel_log_layer)
        .init();

    TelemetryGuard {
        _sentry_guard: Some(sentry_guard),
        _writer_guard: Some(writer_guard),
        _log_provider: log_provider_out,
        _meter_provider: meter_provider_out,
    }
}

/// Obtain a [`Meter`] from the global meter provider.
pub fn meter(name: &'static str) -> Meter {
    opentelemetry::global::meter(name)
}
