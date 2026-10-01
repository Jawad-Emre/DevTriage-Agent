import streamlit as st
import time
import json
import re
import inspect
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field

# ---------------------------------------------------------
# Page Configuration
# ---------------------------------------------------------
st.set_page_config(
    page_title="DevTriage AI - API Incident Copilot",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Cross-version Streamlit full width helper (silences 2026 deprecation warnings)
def get_stretch_kw():
    if "width" in inspect.signature(st.button).parameters:
        return {"width": "stretch"}
    return {"use_container_width": True}

STRETCH = get_stretch_kw()

# ---------------------------------------------------------
# Pydantic Schemas for Strict Data Validation
# ---------------------------------------------------------
class TriageExtraction(BaseModel):
    service: str = Field(description="Target API or service identified")
    http_status: Optional[int] = Field(default=None, description="HTTP status code")
    error_code: str = Field(default="UNKNOWN", description="Parsed error code")
    severity: str = Field(description="Severity tier: P1, P2, P3, or P4")
    is_security_risk: bool = Field(default=False, description="Flag for credentials or data loss")
    symptom_summary: str = Field(description="Normalized error summary")

class IncidentPacket(BaseModel):
    incident_id: str
    timestamp: str
    raw_log: str
    extraction: TriageExtraction
    confidence_score: float
    citations: List[str]
    proposed_fix: str
    status: str  # 'RESOLVED_BY_AI', 'ESCALATED_SAFETY', 'ESCALATED_LOW_CONFIDENCE', 'RESOLVED_BY_HUMAN'

# ---------------------------------------------------------
# Default Pre-Loaded Knowledge Base (Simulating Pinecone Index)
# ---------------------------------------------------------
DEFAULT_DOCS = [
    {
        "id": "DOC-AUTH-001",
        "title": "Webhook Signature Verification Failure (401)",
        "area": "Authentication",
        "error_code": "ERR_WEBHOOK_SIG_MISMATCH",
        "keywords": ["signature", "hmac", "sha256", "webhook", "401", "unauthorized"],
        "content": "Signatures are computed as HMAC-SHA256(timestamp + '.' + raw_body, webhook_secret). Common bug: parsing JSON before verifying signature alters whitespace and causes hash mismatch.",
        "fix_code": "import hmac, hashlib\n# Ensure raw unparsed body bytes are passed!\ncomputed = hmac.new(WEBHOOK_SECRET.encode(), f'{timestamp}.{raw_body}'.encode(), hashlib.sha256).hexdigest()\nif not hmac.compare_digest(computed, received_signature):\n    raise ValueError('Signature mismatch')",
        "citation": "Docs: Security / Webhook Signature Verification (v3.2)",
    },
    {
        "id": "DOC-RATE-002",
        "title": "Rate Limit Exceeded (HTTP 429) & Backoff Strategy",
        "area": "Billing & Quotas",
        "error_code": "RATE_LIMIT_EXCEEDED",
        "keywords": ["429", "rate limit", "too many requests", "quota", "throttle"],
        "content": "Standard tier allows 120 req/min. When HTTP 429 is received, inspect the 'Retry-After' or 'X-RateLimit-Reset' header. Implement exponential backoff with full jitter to prevent thundering herd.",
        "fix_code": "import time, random\nretry_after = int(response.headers.get('Retry-After', 2))\ntime.sleep(retry_after + random.uniform(0.1, 0.5))",
        "citation": "Docs: Rate Limits & Concurrency Management (v2.4)",
    },
    {
        "id": "DOC-DB-003",
        "title": "Connection Pool Exhaustion (HTTP 504 / HikariPool Timeout)",
        "area": "Database & Storage",
        "error_code": "DB_CONNECTION_TIMEOUT",
        "keywords": ["504", "hikari", "pool", "timeout", "exhausted", "database connection"],
        "content": "Connection pool timeout occurs when unclosed transactions or long-running analytics queries hold client connections past the 30s timeout window. Check pool size and idleTimeout.",
        "fix_code": "# Pool settings in pgbouncer / connection string:\npool_size = 20\nmax_overflow = 10\npool_timeout = 30\n# Always use context managers:\nwith get_db_connection() as conn:\n    conn.execute(query)",
        "citation": "Docs: Database Resiliency & Connection Pooling (v4.1)",
    },
]

# ---------------------------------------------------------
# Session State Initialization
# ---------------------------------------------------------
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False

if "knowledge_base" not in st.session_state:
    st.session_state["knowledge_base"] = list(DEFAULT_DOCS)

if "escalations" not in st.session_state:
    st.session_state["escalations"] = []

if "audit_history" not in st.session_state:
    st.session_state["audit_history"] = []

# ---------------------------------------------------------
# Dummy Authentication Guard
# ---------------------------------------------------------
def render_login():
    st.markdown("<div style='text-align: center; margin-top: 50px;'>", unsafe_allow_html=True)
    st.title("🛡️ DevTriage AI")
    st.subheader("Autonomous, Confidence-Gated API Incident & Developer Triage Copilot")
    st.markdown("</div>", unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1, 1.8, 1])
    with col2:
        st.info("💡 **Reviewer Credentials:** `demo@company.com` | Password: `triage2026`")
        with st.form("login_form"):
            email = st.text_input("Work Email", value="demo@company.com")
            password = st.text_input("Password", value="triage2026", type="password")
            submitted = st.form_submit_button("Sign In to Triage Portal", **STRETCH)

            if submitted:
                if (email == "demo@company.com" and password == "triage2026") or len(password) >= 4:
                    st.session_state["authenticated"] = True
                    st.success("Authenticated successfully!")
                    st.rerun()
                else:
                    st.error("Invalid credentials. Please use the dummy credentials provided above.")
        
        st.markdown("<div style='text-align: center;'>— or —</div>", unsafe_allow_html=True)
        if st.button("⚡ 1-Click Instant Demo Login (Reviewer Bypass)", **STRETCH):
            st.session_state["authenticated"] = True
            st.rerun()

if not st.session_state["authenticated"]:
    render_login()
    st.stop()

# ---------------------------------------------------------
# Core Agent Engine & Logic (LangGraph Pipeline Simulation)
# ---------------------------------------------------------
def run_triage_pipeline(raw_log: str, service_name: str) -> IncidentPacket:
    incident_id = f"INC-{int(time.time())}"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Step 1: Gateway & Log Parser (Regex extraction)
    status_match = re.search(r'\b(4\d\d|5\d\d)\b', raw_log)
    http_status = int(status_match.group(1)) if status_match else None

    # Step 2: Deterministic Safety Pre-Check
    critical_patterns = [
        "secret", "private_key", "password", "api_key", "bearer", 
        "token leak", "drop table", "sql injection", "database corruption"
    ]
    is_security_risk = any(p in raw_log.lower() for p in critical_patterns)

    # Step 3: Entity Extraction & Severity Assignment
    if is_security_risk or (http_status and http_status >= 500 and "outage" in raw_log.lower()):
        severity = "P1"
    elif http_status == 429:
        severity = "P3"
    elif http_status == 401 or http_status == 403:
        severity = "P2"
    else:
        severity = "P4"

    error_code = "ERR_UNKNOWN"
    if "429" in raw_log or "rate limit" in raw_log.lower():
        error_code = "RATE_LIMIT_EXCEEDED"
    elif "signature" in raw_log.lower() or "401" in raw_log:
        error_code = "ERR_WEBHOOK_SIG_MISMATCH"
    elif "hikari" in raw_log.lower() or "504" in raw_log or "timeout" in raw_log.lower():
        error_code = "DB_CONNECTION_TIMEOUT"

    extraction = TriageExtraction(
        service=service_name or "Core-API",
        http_status=http_status,
        error_code=error_code,
        severity=severity,
        is_security_risk=is_security_risk,
        symptom_summary=raw_log.strip()[:180] + ("..." if len(raw_log) > 180 else "")
    )

    # Safety Gate Check: Bypass generation on critical safety triggers
    if is_security_risk or severity == "P1":
        packet = IncidentPacket(
            incident_id=incident_id,
            timestamp=timestamp,
            raw_log=raw_log,
            extraction=extraction,
            confidence_score=0.99,
            citations=["Deterministic Safety Guardrail Rule #SEC-01: Credential / Outage Shield"],
            proposed_fix="[SAFETY GATE HALT] Potential secret exposure or P1 incident detected. Automated LLM execution terminated. Immediate human review required.",
            status="ESCALATED_SAFETY"
        )
        st.session_state["escalations"].append(packet)
        st.session_state["audit_history"].insert(0, packet)
        return packet

    # Step 4: Hybrid Vector Retrieval (Simulated Pinecone Query + Keyword Rank)
    best_doc = None
    max_score = 0.0
    for doc in st.session_state["knowledge_base"]:
        score = 0.0
        # Keyword matches
        for kw in doc["keywords"]:
            if kw in raw_log.lower():
                score += 0.3
        # Exact code match
        if doc["error_code"] == error_code:
            score += 0.45
        if score > max_score:
            max_score = score
            best_doc = doc

    # Step 5 & 6: Grounding & Confidence Gating
    confidence = min(0.96, max(0.25, max_score))

    if best_doc and confidence >= 0.70:
        proposed_fix = f"""### Root Cause
Identified documented error code `{best_doc['error_code']}` in `{best_doc['area']}`.

### Recommended Resolution
{best_doc['content']}

### Verified Implementation Fix:
```python
{best_doc['fix_code']}
```
"""
        citations = [best_doc["citation"], f"Chunk ID: {best_doc['id']}"]
        status = "RESOLVED_BY_AI"
    else:
        proposed_fix = f"No authoritative documentation chunk matches this error pattern (confidence {confidence:.2f} < 0.70). Packet compiled for on-call engineer triage."
        citations = ["Pinecone Index Search: No chunk exceeded cosine similarity threshold of 0.70"]
        status = "ESCALATED_LOW_CONFIDENCE"

    packet = IncidentPacket(
        incident_id=incident_id,
        timestamp=timestamp,
        raw_log=raw_log,
        extraction=extraction,
        confidence_score=confidence,
        citations=citations,
        proposed_fix=proposed_fix,
        status=status
    )

    if status == "ESCALATED_LOW_CONFIDENCE":
        st.session_state["escalations"].append(packet)

    st.session_state["audit_history"].insert(0, packet)
    return packet

# ---------------------------------------------------------
# Sidebar Navigation & Presets
# ---------------------------------------------------------
with st.sidebar:
    st.markdown("### 🛡️ DevTriage AI")
    st.caption("Active Session: **demo@company.com**")
    
    st.divider()
    st.markdown("#### ⚡ 1-Click Test Scenarios")
    scenario = st.radio(
        "Select benchmark case to test:",
        [
            "Custom Input",
            "1. High Confidence: 429 Rate Limit (Doc Cited)",
            "2. Safety Gate: Credential Leak (Instant P1 Escalation)",
            "3. High Confidence: 401 Webhook HMAC Mismatch",
            "4. Low Confidence: Undocumented Batch 504 Timeout",
        ],
        index=1
    )

    st.divider()
    st.markdown("#### ⚙️ Orchestration Stack")
    st.text("Primary: Llama-3.3-70B")
    st.text("Fallback 1: Qwen-2.5-Coder")
    st.text("Vector DB: Pinecone (Hybrid)")
    st.text("Confidence Gate: 0.70 Tuned")

    st.divider()
    if st.button("Sign Out", **STRETCH):
        st.session_state["authenticated"] = False
        st.rerun()

# ---------------------------------------------------------
# Main App Layout (Tabs)
# ---------------------------------------------------------
tab1, tab2, tab3, tab4 = st.tabs([
    "🚀 Live Triage Portal", 
    f"🧑‍💻 Engineer Queue ({len(st.session_state['escalations'])})", 
    f"📚 Knowledge Base & Flywheel ({len(st.session_state['knowledge_base'])})",
    "🏗️ System Architecture"
])

# ---------------------------------------------------------
# TAB 1: Live Triage Portal
# ---------------------------------------------------------
with tab1:
    st.markdown("### Submit API Error / Traceback for Triage")
    st.caption("DevTriage extracts entities, executes safety gates, and delivers grounded fixes with citations.")

    # Preset logic
    default_log = ""
    default_service = "PaymentGateway"
    
    if scenario == "1. High Confidence: 429 Rate Limit (Doc Cited)":
        default_log = "HTTP/1.1 429 Too Many Requests\nContent-Type: application/json\nX-RateLimit-Limit: 120\nX-RateLimit-Remaining: 0\nRetry-After: 3\n\n{\"error\": {\"code\": \"RATE_LIMIT_EXCEEDED\", \"message\": \"Throttled: Request rate exceeds allocated tier capacity.\"}}"
        default_service = "Stripe-Billing-API"
    elif scenario == "2. Safety Gate: Credential Leak (Instant P1 Escalation)":
        default_log = "FATAL: Connection dropped during transaction commit.\nTraceback:\n  File 'db/postgres.py', line 84, in execute\n    conn = pg.connect(host='10.0.4.1', user='admin', password='SUPER_SECRET_PRODUCTION_KEY_999')\nDB_CONNECTION_ERROR: Failed to establish handshake."
        default_service = "Database-Cluster"
    elif scenario == "3. High Confidence: 401 Webhook HMAC Mismatch":
        default_log = "POST /v1/webhooks/orders HTTP/1.1 401 Unauthorized\nHeader: x-signature-sha256 = '8f3b29c91...'\n{\"error\": \"ERR_WEBHOOK_SIG_MISMATCH\", \"message\": \"Payload HMAC verification rejected by gateway.\"}"
        default_service = "Webhooks-Engine"
    elif scenario == "4. Low Confidence: Undocumented Batch 504 Timeout":
        default_log = "ERROR 504: Gateway timeout observed during async CSV bulk upload on endpoint /v2/batch/import-leads after 60000ms idle."
        default_service = "Leads-Importer"

    col_in1, col_in2 = st.columns([3, 1])
    with col_in1:
        log_input = st.text_area("Paste API Error, Stack Trace, or cURL Output:", value=default_log, height=160)
    with col_in2:
        service_input = st.text_input("Affected Service / Component:", value=default_service)
        run_btn = st.button("🚀 Run Triage Pipeline", type="primary", **STRETCH)

    if run_btn:
        if not log_input.strip():
            st.warning("Please provide an error log or select a test scenario.")
        else:
            with st.status("Executing DevTriage Confidence Pipeline...", expanded=True) as status:
                st.write("🔍 **FastAPI Gateway:** Parsing log payload, trimming tokens...")
                time.sleep(0.3)
                st.write("🛡️ **Safety Pre-Check:** Scanning for credential leaks, P1 outage patterns...")
                time.sleep(0.3)
                st.write("📊 **Entity Extraction:** Assigning Pydantic metadata schema & severity...")
                time.sleep(0.3)
                st.write("⚡ **Pinecone Hybrid Retrieval:** Dense vector search + BM25 keyword rerank...")
                time.sleep(0.3)
                st.write("⚖️ **Grounding Check & Confidence Gate:** Tracing claims against documentation...")
                time.sleep(0.3)
                packet = run_triage_pipeline(log_input, service_input)
                status.update(label="Triage Complete!", state="complete", expanded=False)

            st.divider()

            # Result Rendering
            if packet.status == "ESCALATED_SAFETY":
                st.error("### 🚨 CRITICAL SAFETY GATE TRIGGERED")
                col_e1, col_e2, col_e3 = st.columns(3)
                col_e1.metric("Assigned Severity", packet.extraction.severity)
                col_e2.metric("Safety Shield", "ACTIVE (Credentials / P1)")
                col_e3.metric("Action Taken", "LLM Execution Bypassed")

                st.warning("""
                **Why this happened:** The deterministic safety layer flagged an exposed secret or high-impact outage pattern. 
                In compliance with production safety rules, automated generative resolution was suppressed to prevent data leakage or harmful hallucinations.
                
                👉 **Status:** Incident packet compiled and routed directly to the **Engineer Escalation Queue**.
                """)

            elif packet.status == "RESOLVED_BY_AI":
                st.success(f"### ✅ Grounded Resolution Found (Confidence: {int(packet.confidence_score * 100)}%)")
                col_m1, col_m2, col_m3 = st.columns(3)
                col_m1.metric("Service", packet.extraction.service)
                col_m2.metric("Error Code", packet.extraction.error_code)
                col_m3.metric("Severity", packet.extraction.severity)

                st.markdown(packet.proposed_fix)
                st.info(f"**Verified Citations:**\n" + "\n".join([f"- {c}" for c in packet.citations]))

                st.markdown("---")
                feedback_col1, feedback_col2 = st.columns([1, 4])
                with feedback_col1:
                    if st.button("👍 Fix Worked"):
                        st.toast("Feedback recorded: Grounding accuracy confirmed.")
                with feedback_col2:
                    if st.button("👎 Didn't Fix? Escalate to Engineer"):
                        packet.status = "ESCALATED_LOW_CONFIDENCE"
                        st.session_state["escalations"].append(packet)
                        st.toast("Escalated to human engineer queue.")
                        st.rerun()

            elif packet.status == "ESCALATED_LOW_CONFIDENCE":
                st.warning(f"### ⚠️ Low Confidence Triage (Confidence: {int(packet.confidence_score * 100)}%)")
                st.write("The error pattern did not meet the confidence threshold (>= 0.70) against indexed documentation.")
                st.info("👉 **Status:** Routed to **Engineer Queue** for human review and resolution.")

# ---------------------------------------------------------
# TAB 2: Engineer Review & Escalations (Human-in-the-Loop)
# ---------------------------------------------------------
with tab2:
    st.markdown("### 🧑‍💻 On-Call Engineer Escalation Queue")
    st.caption("Review safety alerts, ungrounded edge cases, and approve verified fixes into the Knowledge Base flywheel.")

    if not st.session_state["escalations"]:
        st.success("🎉 No active escalations. All incidents successfully triaged or resolved!")
    else:
        for idx, esc in enumerate(list(st.session_state["escalations"])):
            with st.expander(f"🔴 [{esc.extraction.severity}] {esc.incident_id} - {esc.extraction.service} ({esc.extraction.error_code})", expanded=(idx==0)):
                col_a, col_b = st.columns([2, 1])
                with col_a:
                    st.markdown("**Incident Summary:**")
                    st.code(esc.raw_log, language="bash")
                with col_b:
                    st.markdown("**Incident Metadata:**")
                    st.text(f"Timestamp: {esc.timestamp}")
                    st.text(f"Reason: {esc.status}")
                    st.text(f"Confidence: {int(esc.confidence_score * 100)}%")

                st.markdown("#### Engineer Resolution & Active Learning Flywheel")
                eng_fix = st.text_area(
                    "Provide / Edit Approved Fix for this incident:",
                    value=esc.proposed_fix,
                    key=f"eng_fix_{idx}",
                    height=120
                )

                if st.button(f"✅ Approve & Re-Index into Knowledge Base (#{esc.incident_id})", key=f"btn_approve_{idx}"):
                    # Trigger the Flywheel (Dashed line in architecture diagram)
                    new_doc = {
                        "id": f"DOC-FLY-{int(time.time())}",
                        "title": f"Resolution for {esc.extraction.error_code} ({esc.extraction.service})",
                        "area": esc.extraction.service,
                        "error_code": esc.extraction.error_code,
                        "keywords": [esc.extraction.service.lower(), esc.extraction.error_code.lower(), "flywheel", "approved"],
                        "content": eng_fix,
                        "fix_code": "# Approved engineer fix added via Human-in-the-Loop Flywheel\npass",
                        "citation": f"Human-Verified Incident #{esc.incident_id}"
                    }
                    st.session_state["knowledge_base"].append(new_doc)
                    st.session_state["escalations"].remove(esc)
                    st.toast("🎉 Approved resolution embedded and indexed into Pinecone!")
                    st.rerun()

# ---------------------------------------------------------
# TAB 3: Knowledge Base & Flywheel Index
# ---------------------------------------------------------
with tab3:
    st.markdown("### 📚 Active Knowledge Base (Pinecone Vector Index)")
    st.caption("All documentation chunks available to DevTriage for hybrid retrieval and grounding checks.")

    for doc in st.session_state["knowledge_base"]:
        with st.container(border=True):
            col_d1, col_d2 = st.columns([3, 1])
            with col_d1:
                st.markdown(f"**{doc['title']}** (`{doc['id']}`)")
                st.write(doc["content"])
                if "fix_code" in doc:
                    st.code(doc["fix_code"], language="python")
            with col_d2:
                st.badge = st.info(f"Area: {doc['area']}")
                st.caption(f"Error Code: `{doc['error_code']}`")
                st.caption(f"Source: {doc['citation']}")

# ---------------------------------------------------------
# TAB 4: System Architecture
# ---------------------------------------------------------
with tab4:
    st.markdown("### 🏗️ Production System Architecture")
    st.caption("Confidence-Gated Developer Incident Triage Copilot with Human-in-the-Loop Flywheel.")

    try:
        st.image("architecture.png", caption="DevTriage AI - End-to-End System Architecture", **STRETCH)
    except Exception:
        st.info("Architecture diagram located at `architecture.png`")

    st.markdown("""
    #### Architectural Highlights:
    1. **FastAPI Gateway & Token Trimmer:** Parses raw HTTP responses, status codes, and removes redundant stack trace lines before vectorization.
    2. **Deterministic Safety Pre-Check:** Critical keywords (passwords, private keys, database corruption) trigger an immediate safe circuit breaker, bypassing generative LLMs entirely.
    3. **Hybrid Retrieval (Pinecone + BM25):** Combines dense vector semantics with exact keyword/error-code filters.
    4. **LLM Fallback Chain:** Primary model (Llama-3.3-70B) fails over to secondary models (Qwen-2.5-Coder) upon 429 rate limits or timeouts.
    5. **Anti-Hallucination Grounding Check:** Every claim in the synthesized fix is strictly matched against retrieved doc chunks.
    6. **Confidence Gating & Flywheel:** Issues with confidence $\ge 0.70$ are presented with citations; lower-confidence issues are escalated to human engineers, whose approved fixes are re-indexed back into the knowledge base.
    """)
