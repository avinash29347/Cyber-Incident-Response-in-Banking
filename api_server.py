from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
import json
from pathlib import Path

from layer_1_feature_engineering.ingestion_orchestrator import process_json_text
from layer_2_detection.detection_orchestrator import run_detection_batch
from layer_3_cis.orchestrator import run_layer3
from frontend_formatter import format_pipeline_for_frontend
from layer_4_ai_analysis.incident_report_builder import run_layer4
from layer_5_cvss.cvss_orchestrator import run_cvss
from layer_6_response.response_orchestrator import run_response

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).resolve().parent
OUTPUT_PATH = BASE_DIR / "Frontend" / "public" / "frontend_output.json"


@app.post("/run-pipeline")
async def run_pipeline(file: UploadFile = File(...)):
    content = await file.read()
    content_str = content.decode("utf-8")

    # Layer 1
    normalized = process_json_text(content_str)
    from layer_1_feature_engineering.feature_orchestrator import run_feature_engineering
    layer1 = [run_feature_engineering(rec) for rec in normalized]

    # Layer 2
    layer2 = run_detection_batch(layer1)

    # Layer 3
    layer3 = run_layer3(layer2)

    # Frontend format
    frontend_output = format_pipeline_for_frontend(
        parsed_logs=None,
        layer1_output=layer1,
        layer2_output=layer2,
        layer3_output=layer3,
    )

    # Layer 4
    enriched = run_layer4(frontend_output["events"])

    for event in enriched:
        event["cvss"] = run_cvss(event["ai_analysis"])
        event["response"] = run_response(event)

    frontend_output["events"] = enriched

    # Save to frontend
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(frontend_output, f, indent=2)

    return {"status": "success", "events": len(enriched)}