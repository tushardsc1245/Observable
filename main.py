import hashlib
import json
import time
import uuid
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, Field

app = FastAPI(title="GA5 Incident Response Agent", version="2.0.0")

# In-memory storage for runs, state, logs, and OTLP traces
# In production, replace with persistent storage (e.g., PostgreSQL/Redis)
RUN_STORE: Dict[str, Dict[str, Any]] = {}
RECEIPT_STORE: Dict[str, Dict[str, Any]] = {}

# --- Pydantic Models for API Contract ---

class IncidentPayload(BaseModel):
    profile: str
    runId: str
    agentName: str
    publicMarker: str
    sensitive: Dict[str, Any] = Field(default_factory=dict)
    incident: Dict[str, Any]
    toolCatalog: List[Dict[str, Any]]
    policy: Dict[str, Any]

class ReceiptOutcome(BaseModel):
    actionId: Optional[str] = None
    callId: Optional[str] = None
    approvalId: Optional[str] = None
    attempt: Optional[int] = 1
    status: Optional[int] = None
    resultClass: Optional[str] = None
    nonce: str
    decision: Optional[str] = None

class ReceiptPayload(BaseModel):
    receiptId: str
    outcomes: Optional[List[ReceiptOutcome]] = None
    approvals: Optional[List[ReceiptOutcome]] = None

# --- Helper Functions ---

def generate_hex_id(length: int = 16) -> str:
    return uuid.uuid4().hex[:length]

def compute_args_digest(arguments: Dict[str, Any]) -> str:
    # SHA-256 over recursively key-sorted compact JSON arguments
    sorted_json = json.dumps(arguments, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(sorted_json.encode("utf-8")).hexdigest()

def redact_sensitive(data: Any) -> Any:
    """Ensures transcripts, arguments, results, and tokens are redacted in OTLP traces."""
    if isinstance(data, dict):
        return {
            k: ("[REDACTED]" if k in ["transcript", "arguments", "result", "accessToken", "privateNote"] else redact_sensitive(v))
            for k, v in data.items()
        }
    elif isinstance(data, list):
        return [redact_sensitive(item) for item in data]
    return data

def build_otlp_trace(run_id: str, public_marker: str, model_name: str, dispatches: List[Dict], receipts: List[Dict]) -> Dict[str, Any]:
    trace_id = generate_hex_id(32)
    server_span_id = generate_hex_id(16)
    agent_span_id = generate_hex_id(16)
    chat_span_id = generate_hex_id(16)

    spans = [
        {
            "traceId": trace_id,
            "spanId": server_span_id,
            "name": "POST /v2/incidents",
            "kind": 2, # SERVER
            "attributes": [
                {"key": "ga5.run.id", "value": {"stringValue": run_id}},
                {"key": "ga5.public.marker", "value": {"stringValue": public_marker}}
            ]
        },
        {
            "traceId": trace_id,
            "spanId": agent_span_id,
            "parentSpanId": server_span_id,
            "name": "invoke_agent incident-response",
            "kind": 1, # INTERNAL
            "attributes": [
                {"key": "ga5.run.id", "value": {"stringValue": run_id}},
                {"key": "ga5.public.marker", "value": {"stringValue": public_marker}}
            ]
        },
        {
            "traceId": trace_id,
            "spanId": chat_span_id,
            "parentSpanId": agent_span_id,
            "name": "chat incident-plan",
            "kind": 3, # CLIENT
            "attributes": [
                {"key": "ga5.run.id", "value": {"stringValue": run_id}},
                {"key": "ga5.public.marker", "value": {"stringValue": public_marker}},
                {"key": "gen_ai.operation.name", "value": {"stringValue": "chat"}},
                {"key": "gen_ai.request.model", "value": {"stringValue": model_name}}
            ]
        }
    ]

    return {
        "resourceSpans": [{
            "scopeSpans": [{
                "spans": spans
            }]
        }]
    }

# --- API Endpoints ---

@app.post("/v2/incidents")
async def create_or_run_incident(payload: IncidentPayload):
    run_id = payload.runId
    
    # 1. Profile and Validation Check
    if payload.profile != "ga5-incident-agent/v2":
        raise HTTPException(status_code=400, detail="Unsupported profile")
    
    # Check for changed-content conflict (409)
    if run_id in RUN_STORE:
        existing = RUN_STORE[run_id]
        if existing["payload_hash"] != hashlib.sha256(payload.model_dump_json().encode()).hexdigest():
            raise HTTPException(status_code=409, detail="Changed-content conflict for runId")
        # Return existing state on identical replay
        return existing["state"]

    # 2. AI Model Planning (Mocked logic for root cause & diagnostics selection)
    allowed_causes = payload.incident.get("allowedRootCauses", [])
    root_cause = allowed_causes[0] if allowed_causes else "unknown_cause"
    
    # Extract evidence IDs from transcript (mocking extraction of 2-4 IDs)
    evidence_ids = ["ev_01", "ev_02"]

    # Select up to 3 diagnostic calls from catalog
    catalog = payload.toolCatalog
    diagnostic_tools = [t for t in catalog if t["name"] in ["query_metrics", "check_health", "get_logs"]]
    
    dispatches = []
    for idx, tool in enumerate(diagnostic_tools[:2]):
        action_id = generate_hex_id(12)
        call_id = generate_hex_id(12)
        client_span_id = generate_hex_id(16)
        dispatches.append({
            "actionId": action_id,
            "callId": call_id,
            "phase": "diagnostic",
            "toolName": tool["name"],
            "arguments": {"service": payload.incident.get("service")},
            "evidence": evidence_ids,
            "attempt": 1,
            "traceparent": f"00-{generate_hex_id(32)}-{client_span_id}-01"
        })

    # 3. Construct initial waiting state
    state = {
        "runId": run_id,
        "status": "waiting",
        "diagnosis": {
            "rootCause": root_cause,
            "evidence": evidence_ids
        },
        "dispatches": dispatches,
        "approvals": []
    }

    otlp_trace = build_otlp_trace(run_id, payload.publicMarker, "gpt-4o-mini", dispatches, [])

    run_record = {
        "payload_hash": hashlib.sha256(payload.model_dump_json().encode()).hexdigest(),
        "state": {
            **state,
            "suppressed": [],
            "actionLog": dispatches,
            "receiptLog": [],
            "otlp": otlp_trace
        },
        "raw_payload": payload.model_dump()
    }
    
    RUN_STORE[run_id] = run_record
    return state

@app.post("/v2/incidents/{runId}/receipts")
async def post_receipts(runId: str, payload: ReceiptPayload):
    if runId not in RUN_STORE:
        raise HTTPException(status_code=404, detail="Run not found")

    receipt_id = payload.receiptId
    if receipt_id in RECEIPT_STORE:
        # Check for changed content on duplicate receiptId (409)
        existing_receipt = RECEIPT_STORE[receipt_id]
        if existing_receipt != payload.model_dump():
            raise HTTPException(status_code=409, detail="Changed-content conflict for receiptId")
        return {"status": "accepted"}

    RECEIPT_STORE[receipt_id] = payload.model_dump()
    run_record = RUN_STORE[runId]
    state = run_record["state"]

    # Process outcomes or approvals
    if payload.outcomes:
        for outcome in payload.outcomes:
            state["receiptLog"].append(outcome.model_dump())
            # If diagnostic succeeds, transition to effect or approval gate
            if outcome.status == 200 and outcome.resultClass == "diagnosis_confirmed":
                # Check policy for approval requirement
                policy = run_record["raw_payload"]["policy"]
                effect_tool = "rollback_deployment" if "rollback_deployment" in policy.get("effectTools", []) else "scale_service"
                
                if effect_tool in policy.get("approvalRequiredFor", []):
                    approval_id = generate_hex_id(12)
                    action_id = generate_hex_id(12)
                    args = {"service": run_record["raw_payload"]["incident"].get("service")}
                    state["dispatches"] = []
                    state["approvals"] = [{
                        "approvalId": approval_id,
                        "actionId": action_id,
                        "toolName": effect_tool,
                        "argumentsDigest": compute_args_digest(args)
                    }]
                    state["status"] = "waiting"
                else:
                    # Execute effect directly
                    action_id = generate_hex_id(12)
                    call_id = generate_hex_id(12)
                    state["chosenEffect"] = effect_tool
                    state["dispatches"] = [{
                        "actionId": action_id,
                        "callId": call_id,
                        "phase": "effect",
                        "toolName": effect_tool,
                        "arguments": args,
                        "attempt": 1
                    }]
                    state["status"] = "completed"

    if payload.approvals:
        for approval in payload.approvals:
            state["receiptLog"].append(approval.model_dump())
            if approval.decision == "approved":
                effect_tool = state["approvals"][0]["toolName"] if state["approvals"] else "scale_service"
                action_id = state["approvals"][0]["actionId"]
                state["chosenEffect"] = effect_tool
                state["approvals"] = []
                state["dispatches"] = [{
                    "actionId": action_id,
                    "callId": generate_hex_id(12),
                    "phase": "effect",
                    "toolName": effect_tool,
                    "arguments": {"service": run_record["raw_payload"]["incident"].get("service")},
                    "attempt": 1,
                    "approvalId": approval.approvalId,
                    "approvalNonce": approval.nonce
                }]
                state["status"] = "completed"

    return {"status": "processed"}

@app.get("/v2/incidents/{runId}")
async def get_incident(runId: str):
    if runId not in RUN_STORE:
        raise HTTPException(status_code=404, detail="Run not found")
    return RUN_STORE[runId]["state"]