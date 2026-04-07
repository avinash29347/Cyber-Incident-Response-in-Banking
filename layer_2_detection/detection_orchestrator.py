from layer_2_detection.engine_1_anomaly.anomaly_orchestrator import run_anomaly
from layer_2_detection.engine_2_threat_analysis.threat_analysis_orchestrator import run_threat_analysis
from layer_2_detection.engine_3_ioc_enrichment.ioc_orchestrator import run_ioc_enrichment
from layer_2_detection.engine_4_correlation.correlation_orchestrator import run_correlation
from layer_2_detection.detection_fusion import fuse_detection
from layer_2_detection.layer1_adapter import adapt_layer1_event


def run_detection(event: dict) -> dict:
    event = adapt_layer1_event(event)
    event = run_anomaly(event)
    event = run_threat_analysis(event)
    event = run_ioc_enrichment(event)
    event = run_correlation(event)
    event = fuse_detection(event)
    return event


def run_detection_batch(events: list[dict]) -> dict:
    return {
        "status": "success",
        "detections": [run_detection(event) for event in events]
    }