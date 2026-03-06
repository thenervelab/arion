use sentry::ClientInitGuard;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

/// Initialize tracing and sentry
pub fn init_tracing_and_sentry(default_filter: &str) -> Option<ClientInitGuard> {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));

    let sentry_dsn = std::env::var("SENTRY_DSN").unwrap_or_else(|_| {
        "http://4bd9d6e990f8f0129bf80bd408c6ebc8@sentry-relay.sentry.svc.cluster.local:3000/2"
            .to_string()
    });

    // Initialize sentry
    let guard = sentry::init((
        sentry_dsn,
        sentry::ClientOptions {
            release: sentry::release_name!(),
            traces_sample_rate: 1.0,
            debug: true,
            ..Default::default()
        },
    ));

    // Initialize tracing subscriber
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .with(sentry_tracing::layer())
        .init();

    Some(guard)
}
