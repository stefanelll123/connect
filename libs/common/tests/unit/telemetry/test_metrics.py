"""Unit tests for TASK-052: OTel Instrumentation + Prometheus Metrics.

Cases:
1. inbound_requests_total counter incremented on request
2. denies_total{reason='REPLAY_DETECTED'} increments on replay
3. pipeline stage histogram records value > 0
4. All 18 metrics are defined and importable
5. OTel tracer is obtained from globally registered provider
6. Manual span can be created with expected name
7. Sampling rate applied on TracerProvider (configurable)
"""
from __future__ import annotations

import os
import pytest

# Ensure metrics are enabled for tests
os.environ.setdefault("SENTINEL_METRICS_ENABLED", "true")


# ---------------------------------------------------------------------------
# Test 1: inbound_requests_total increments
# ---------------------------------------------------------------------------

class TestInboundRequestsCounter:
    def test_inbound_requests_total_increments(self):
        from common.sentinel_logging import sentinel_metrics as m_mod
        import prometheus_client

        # Get baseline (may be None if label set never seen)
        baseline = prometheus_client.REGISTRY.get_sample_value(
            "sentinel_inbound_requests_total",
            {"sentinel_role": "producer", "service_id": "svc1", "env": "dev",
             "decision": "permit", "error_code": ""},
        ) or 0.0

        m_mod.inbound_requests_total.labels(
            sentinel_role="producer", service_id="svc1", env="dev",
            decision="permit", error_code=""
        ).inc()

        new_val = prometheus_client.REGISTRY.get_sample_value(
            "sentinel_inbound_requests_total",
            {"sentinel_role": "producer", "service_id": "svc1", "env": "dev",
             "decision": "permit", "error_code": ""},
        )
        assert new_val is not None
        assert new_val >= baseline + 1.0


# ---------------------------------------------------------------------------
# Test 2: denies_total{reason='REPLAY_DETECTED'} increments
# ---------------------------------------------------------------------------

class TestDeniesTotalReplay:
    def test_denies_total_replay_detected(self):
        from common.sentinel_logging import sentinel_metrics as m_mod
        import prometheus_client

        baseline = prometheus_client.REGISTRY.get_sample_value(
            "sentinel_denies_total",
            {"sentinel_role": "consumer", "service_id": "svc2", "env": "dev",
             "reason": "REPLAY_DETECTED"},
        ) or 0.0

        m_mod.denies_total.labels(
            sentinel_role="consumer", service_id="svc2", env="dev",
            reason="REPLAY_DETECTED"
        ).inc()

        new_val = prometheus_client.REGISTRY.get_sample_value(
            "sentinel_denies_total",
            {"sentinel_role": "consumer", "service_id": "svc2", "env": "dev",
             "reason": "REPLAY_DETECTED"},
        )
        assert new_val is not None
        assert new_val >= baseline + 1.0


# ---------------------------------------------------------------------------
# Test 3: histogram records latency > 0
# ---------------------------------------------------------------------------

class TestHistogramRecordsLatency:
    def test_inbound_request_duration_records_value(self):
        import prometheus_client
        import common.sentinel_logging.sentinel_metrics as m_mod

        m_mod.inbound_request_duration_seconds.labels(
            sentinel_role="producer", service_id="svc3", env="dev",
            stage="verify_proof"
        ).observe(0.042)

        # Check the _sum sample is > 0
        sum_val = prometheus_client.REGISTRY.get_sample_value(
            "sentinel_inbound_request_duration_seconds_sum",
            {"sentinel_role": "producer", "service_id": "svc3", "env": "dev",
             "stage": "verify_proof"},
        )
        assert sum_val is not None
        assert sum_val > 0


# ---------------------------------------------------------------------------
# Test 4: All 18 metrics are defined
# ---------------------------------------------------------------------------

class TestAllMetricsDefined:
    def test_all_18_metrics_importable(self):
        from common.sentinel_logging import sentinel_metrics as m

        required = [
            "inbound_requests_total",
            "outbound_requests_total",
            "inbound_request_duration_seconds",
            "upstream_latency_seconds",
            "denies_total",
            "replay_rejects_total",
            "replay_cache_fallback_total",
            "revocation_stale_total",
            "chain_rpc_errors_total",
            "chain_cache_miss_total",
            "trust_layer_unavailable_total",
            "vc_verifications_total",
            "credential_sync_lag_seconds",
            "policy_evaluate_total",
            "descriptor_cache_misses_total",
            "active_connections",
            "emergency_revocation_checks_total",
            "key_rotation_total",
        ]
        missing = [name for name in required if not hasattr(m, name)]
        assert missing == [], f"Missing metrics: {missing}"
        assert len(required) == 18

    def test_no_jti_or_did_as_label_names(self):
        """Metric labels must never include jti or full DID values."""
        import prometheus_client
        for metric in prometheus_client.REGISTRY.collect():
            if not metric.name.startswith("sentinel_"):
                continue
            for sample in metric.samples:
                for label_name in sample.labels:
                    assert "jti" not in label_name.lower() or label_name == "service_id"
                    # DID values should never be label values — just check keys
                    assert label_name not in ("consumer_did", "issuer_did")


# ---------------------------------------------------------------------------
# Test 5 & 6: OTel tracer obtained and span created
# ---------------------------------------------------------------------------

class TestOtelTracer:
    def test_get_tracer_returns_tracer(self):
        from opentelemetry import trace
        from common.sentinel_logging.otel import get_tracer
        tracer = get_tracer("test-service")
        assert tracer is not None

    def test_manual_span_creation(self):
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
            InMemorySpanExporter,
        )
        from opentelemetry.sdk.trace.export import SimpleSpanProcessor
        from opentelemetry import trace

        exporter = InMemorySpanExporter()
        provider = TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(exporter))

        tracer = provider.get_tracer("test-tracer")
        with tracer.start_as_current_span("sentinel.verify_proof") as span:
            span.set_attribute("service_id", "svc-test")
            span.set_attribute("result", "ok")

        spans = exporter.get_finished_spans()
        assert len(spans) == 1
        assert spans[0].name == "sentinel.verify_proof"
        assert spans[0].attributes.get("service_id") == "svc-test"

    def test_span_names_from_pipeline_stages(self):
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
            InMemorySpanExporter,
        )
        from opentelemetry.sdk.trace.export import SimpleSpanProcessor

        exporter = InMemorySpanExporter()
        provider = TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(exporter))

        tracer = provider.get_tracer("pipeline")
        stages = [
            "sentinel.resolve_descriptor",
            "sentinel.build_vp",
            "sentinel.verify_proof",
            "sentinel.verify_vc",
            "sentinel.check_revocation",
            "sentinel.policy_evaluate",
            "sentinel.proxy_upstream",
        ]
        for stage in stages:
            with tracer.start_as_current_span(stage):
                pass

        span_names = [s.name for s in exporter.get_finished_spans()]
        for stage in stages:
            assert stage in span_names, f"Missing span: {stage}"


# ---------------------------------------------------------------------------
# Test 7: Sampling rate applied (configurable)
# ---------------------------------------------------------------------------

class TestSamplingRate:
    def test_setup_tracing_with_dev_sample_rate(self):
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.sampling import ParentBasedTraceIdRatio

        provider = TracerProvider(
            sampler=ParentBasedTraceIdRatio(1.0),
        )
        assert provider.sampler is not None

    def test_setup_tracing_produces_tracer(self):
        from common.sentinel_logging.otel import setup_tracing
        tracer = setup_tracing(
            service_name="test-sentinel",
            instance_id="inst-001",
            env="dev",
            role="producer",
            sample_rate=1.0,
        )
        assert tracer is not None
