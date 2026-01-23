use std::sync::Arc;

use anyhow::{Context, Result};
use prometheus::{HistogramTimer, IntGauge, core::Collector};

use crate::{METRICS, Metrics};

#[inline]
pub fn set_gauge_u64(
    metric_getter: impl FnOnce(&Arc<Metrics>) -> &IntGauge,
    value_getter: impl FnOnce() -> Result<u64>,
) {
    METRICS.get().map(|v| {
        let metric = metric_getter(v);

        let _ = value_getter()
            .and_then(|value| {
                metric.set(value.try_into().context("invalid metric value")?);
                Ok(())
            })
            .inspect_err(|err| {
                let desc = metric.desc();

                tracing::warn!(
                    "failed to set metric {metric_name} with error: {err:?}",
                    metric_name = desc
                        .get(0)
                        .map(|v| v.fq_name.clone())
                        .unwrap_or("<unknown_metric>".to_owned())
                )
            });
    });
}

pub fn stop_and_record(timer: Option<HistogramTimer>) {
    if let Some(timer) = timer {
        timer.stop_and_record();
    }
}

pub fn stop_and_discard(timer: Option<HistogramTimer>) {
    if let Some(timer) = timer {
        timer.stop_and_discard();
    }
}
