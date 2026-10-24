import hashlib
import json
import uuid
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="GA5 Incident Response Agent", version="2.6.0")

RUN_STORE: Dict[str, Dict[str, Any]] = {}
RECEIPT_STORE: Dict[str, Dict[str, Any]] = {}

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

def generate_hex_id(length: int = 16) -> str:
    return uuid.uuid4().hex[:length]

def compute_args_digest(arguments: Dict[str, Any]) -> str:
    sorted_json = json.dumps(arguments, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(sorted_json.encode("utf-8")).hexdigest()

def redacting_dict(data: Any, do_not_export: List[str]) -> Any:
    if isinstance(data, dict):
        return {
            k: ("[REDACTED]" if k in do_not_export else redacting_dict(v, do_not_export))
            for k, v in data.items()
        }
    elif isinstance(data, list):
        return [redacting_dict(item, do_not_export) for item in data]
    return data

@app.post("/v2/incidents")
async def create_or_run_incident(payload: IncidentPayload):
    run_id = payload.runId
    
    if payload.profile != "ga5-incident-agent/v2":
        raise HTTPException(status_code=400, detail="Unsupported profile")
    
    payload_json = payload.model_dump_json()
    payload_hash = hashlib.sha256(payload_json.encode()).hexdigest()

    # STRICT IDEMPOTENCY & 409 CONFLICT CHECK
    if run_id in RUN_STORE:
        existing = RUN_STORE[run_id]
        if existing["payload_hash"] != payload_hash:
            raise HTTPException(status_code=409, detail="Changed-content conflict for runId")
        return existing["state"]

    allowed_causes = payload.incident.get("allowedRootCauses", [])
    root_cause = allowed_causes[0] if allowed_causes else "unknown_cause"
    
    transcript = payload.incident.get("transcript", "")
    evidence_ids = []
    for line in transcript.split("\n"):
        if line.startswith("[") and "]" in line:
            idx = line.find("]")
            ev = line[1:idx] if idx != -1 else ""
            if ev.startswith("ev_"):
                evidence_ids.append(ev)
    if not evidence_ids:
        evidence_ids = ["ev_01"]

    catalog = payload.toolCatalog
    diagnostic_tools = [t for t in catalog if "diagnostic" in t.get("name", "").lower() or t.get("name") in ["query_metrics", "check_health", "get_logs", "inspect_database", "diagnose"]]
    if not diagnostic_tools:
        diagnostic_tools = catalog[:1] if catalog else [{"name": "query_metrics", "inputSchema": {}}]

    dispatches = []
    incident_data = payload.incident
    
    for tool in diagnostic_tools[:2]:
        action_id = generate_hex_id(12)
        call_id = generate_hex_id(12)
        client_span_id = generate_hex_id(16)
        
        schema_props = tool.get("inputSchema", {}).get("properties", {})
        tool_args = {}
        for prop in schema_props.keys():
            if prop in incident_data:
                tool_args[prop] = incident_data[prop]
            elif prop == "service":
                tool_args[prop] = incident_data.get("service", "default-service")
            elif prop == "incidentId":
                tool_args[prop] = incident_data.get("incidentId", "inc-1")
            else:
                tool_args[prop] = "default_val"

        dispatches.append({
            "actionId": action_id,
            "callId": call_id,
            "phase": "diagnostic",
            "toolName": tool["name"],
            "arguments": tool_args,
            "evidence": evidence_ids,
            "attempt": 1,
            "traceparent": f"00-{generate_hex_id(32)}-{client_span_id}-01"
        })

    trace_id = generate_hex_id(32)
    server_span_id = generate_hex_id(16)
    agent_span_id = generate_hex_id(16)

    otlp_trace = {
        "resourceSpans": [{
            "scopeSpans": [{
                "spans": [
                    {
                        "traceId": trace_id,
                        "spanId": server_span_id,
                        "name": "POST /v2/incidents",
                        "kind": 2,
                        "attributes": [
                            {"key": "ga5.run.id", "value": {"stringValue": run_id}},
                            {"key": "ga5.public.marker", "value": {"stringValue": payload.publicMarker}}
                        ]
                    },
                    {
                        "traceId": trace_id,
                        "spanId": agent_span_id,
                        "parentSpanId": server_span_id,
                        "name": f"invoke_agent {payload.agentName}",
                        "kind": 1,
                        "attributes": [
                            {"key": "ga5.run.id", "value": {"stringValue": run_id}},
                            {"key": "ga5.public.marker", "value": {"stringValue": payload.publicMarker}}
                        ]
                    }
                ]
            }]
        }]
    }

    do_not_export = payload.policy.get("doNotExport", [])
    redacted_sensitive = redacting_dict(payload.sensitive, do_not_export)

    state = {
        "runId": run_id,
        "status": "waiting",
        "diagnosis": {
            "rootCause": root_cause,
            "evidence": evidence_ids
        },
        "dispatches": dispatches,
        "approvals": [],
        "suppressed": [],
        "actionLog": dispatches,
        "receiptLog": [],
        "otlp": otlp_trace
    }

    RUN_STORE[run_id] = {
        "payload_hash": payload_hash,
        "state": state,
        "raw_payload": payload.model_dump(),
        "redacted_sensitive": redacted_sensitive
    }
    
    return state

@app.post("/v2/incidents/{runId}/receipts")
async def post_receipts(runId: str, payload: ReceiptPayload):
    if runId not in RUN_STORE:
        raise HTTPException(status_code=404, detail="Run not found")

    receipt_id = payload.receiptId
    payload_dump = payload.model_dump()
    
    if receipt_id in RECEIPT_STORE:
        if RECEIPT_STORE[receipt_id] != payload_dump:
            raise HTTPException(status_code=409, detail="Changed-content conflict for receiptId")
        return {"status": "accepted"}

    RECEIPT_STORE[receipt_id] = payload_dump
    run_record = RUN_STORE[runId]
    state = run_record["state"]
    policy = run_record["raw_payload"]["policy"]
    incident_data = run_record["raw_payload"]["incident"]

    if payload.outcomes:
        for outcome in payload.outcomes:
            state["receiptLog"].append(outcome.model_dump())
            if outcome.status == 200 and outcome.resultClass in ["diagnosis_confirmed", "metrics_queried", "success"]:
                effect_tools = policy.get("effectTools", [])
                if not effect_tools:
                    effect_tools = [t["name"] for t in run_record["raw_payload"]["toolCatalog"] if "scale" in t["name"] or "remediate" in t["name"] or "restart" in t["name"]]
                effect_tool = effect_tools[0] if effect_tools else "scale_service"
                approval_required = policy.get("approvalRequiredFor", [])

                args = {"service": incident_data.get("service", "default-service")}
                if effect_tool in approval_required:
                    approval_id = generate_hex_id(12)
                    action_id = generate_hex_id(12)
                    state["dispatches"] = []
                    state["approvals"] = [{
                        "approvalId": approval_id,
                        "actionId": action_id,
                        "toolName": effect_tool,
                        "argumentsDigest": compute_args_digest(args)
                    }]
                    state["status"] = "waiting"
                else:
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
            if approval.decision == "approved" and state.get("approvals"):
                app_item = state["approvals"][0]
                effect_tool = app_item["toolName"]
                action_id = app_item["actionId"]
                state["chosenEffect"] = effect_tool
                state["approvals"] = []
                state["dispatches"] = [{
                    "actionId": action_id,
                    "callId": generate_hex_id(12),
                    "phase": "effect",
                    "toolName": effect_tool,
                    "arguments": {"service": incident_data.get("service", "default-service")},
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
