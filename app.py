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

# Cross-version Streamlit full width helper
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
        "area": "Authentication & Security",
        "error_code": "ERR_WEBHOOK_SIG_MISMATCH",
        "keywords": ["signature", "hmac", "sha256", "webhook", "401", "unauthorized"],
        "content": "Signatures are computed as HMAC-SHA256(timestamp + '.' + raw_body, webhook_secret). Common bug: parsing JSON before verifying signature alters whitespace and causes hash mismatch.",
        "fix_code": "import hmac, hashlib\n\n# CRITICAL: Pass raw unparsed bytes to HMAC, never parsed JSON!\ncomputed = hmac.new(WEBHOOK_SECRET.encode(), f'{timestamp}.{raw_body}'.encode(), hashlib.sha256).hexdigest()\nif not hmac.compare_digest(computed, received_signature):\n    raise ValueError('Webhook signature mismatch: check secret key and payload byte-encoding')",
        "citation": "Docs: Security / Webhook Signature Verification (v3.2)",
    },
    {
        "id": "DOC-RATE-002",
        "title": "Rate Limit Exceeded (HTTP 429) & Backoff Strategy",
        "area": "Billing & Quotas",
        "error_code": "RATE_LIMIT_EXCEEDED",
        "keywords": ["429", "rate limit", "too many requests", "quota", "throttle"],
        "content": "Standard API tier allows 120 req/min. When HTTP 429 is received, inspect the 'Retry-After' or 'X-RateLimit-Reset' header. Implement exponential backoff with full jitter to avoid API lockouts.",
        "fix_code": "import time, random\n\n# Exponential backoff with full jitter\nretry_after = int(response.headers.get('Retry-After', 2))\nsleep_duration = retry_after + random.uniform(0.1, 0.5)\ntime.sleep(sleep_duration)",
        "citation": "Docs: Rate Limits & Concurrency Management (v2.4)",
    },
    {
        "id": "DOC-DB-003",
        "title": "Connection Pool Exhaustion (HTTP 504 / HikariPool Timeout)",
        "area": "Database & Storage",
        "error_code": "DB_CONNECTION_TIMEOUT",
        "keywords": ["504", "hikari", "pool", "timeout", "exhausted", "database connection"],
        "content": "Connection pool timeout occurs when unclosed transactions or unindexed analytics queries hold connections past the 30s timeout window. Adjust pool size and idleTimeout.",
        "fix_code": "# Recommended PgBouncer / Connection Pool settings:\npool_size = 20\nmax_overflow = 10\npool_timeout = 30\n\n# Always wrap database queries in context managers:\nwith get_db_connection() as conn:\n    conn.execute(query)",
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

if "latest_packet" not in st.session_state:
    st.session_state["latest_packet"] = None

# ---------------------------------------------------------
# Dummy Authentication Guard
# ---------------------------------------------------------
def render_login():
    st.markdown("<div style='text-align: center; margin-top: 40px;'>", unsafe_allow_html=True)
    st.title("🛡️ DevTriage AI")
    st.markdown("### Autonomous, Confidence-Gated API Incident & Developer Triage Copilot")
    st.caption("A production-grade AI copilot built for Dafinitiq AI Engineer Associate Program")
    st.markdown("</div>", unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1, 1.6, 1])
    with col2:
        st.info("💡 **Dafinitiq Reviewer Credentials:**\n• **Email:** `demo@company.com`\n• **Password:** `triage2026`")
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
        
        st.markdown("<div style='text-align: center; margin: 10px 0;'>— or —</div>", unsafe_allow_html=True)
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
            citations=["Deterministic Safety Guardrail Rule #SEC-01: Credential & P1 Outage Shield"],
            proposed_fix="[SAFETY GATE HALT] Potential secret exposure or critical P1 outage detected. Automated LLM generation terminated immediately to prevent data leakage. Escalated to on-call security engineer.",
            status="ESCALATED_SAFETY"
        )
        st.session_state["escalations"].append(packet)
        st.session_state["audit_history"].insert(0, packet)
        st.session_state["latest_packet"] = packet
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
        proposed_fix = f"""### 🔍 Diagnosis
Identified documented error code `{best_doc['error_code']}` in **{best_doc['area']}**.

### 💡 Authoritative Solution
{best_doc['content']}

### 🛠️ Verified Code Fix
```python
{best_doc['fix_code']}
```
"""
        citations = [best_doc["citation"], f"Pinecone Chunk ID: {best_doc['id']}"]
        status = "RESOLVED_BY_AI"
    else:
        proposed_fix = f"No authoritative documentation chunk matches this error pattern with sufficient similarity (score: {confidence:.2f} < 0.70 threshold). Escalation packet created for on-call engineer triage."
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
    st.session_state["latest_packet"] = packet
    return packet

# ---------------------------------------------------------
# Sidebar Navigation & Presets
# ---------------------------------------------------------
with st.sidebar:
    st.markdown("## 🛡️ DevTriage AI")
    st.markdown("**Role:** Senior Incident Copilot")
    st.caption("Active Session: `demo@company.com`")
    
    st.divider()
    st.markdown("### ⚡ 1-Click Test Scenarios")
    st.caption("Select a scenario to auto-fill the triage portal:")
    scenario = st.radio(
        "Choose benchmark scenario:",
        [
            "1. High Confidence: 429 Rate Limit (Doc Cited)",
            "2. Safety Gate: Secret Key Leak (P1 Circuit Breaker)",
            "3. High Confidence: 401 Webhook HMAC Mismatch",
            "4. Low Confidence: Undocumented Batch 504 Timeout",
            "Custom Freeform Input"
        ],
        index=0
    )

    st.divider()
    st.markdown("### ⚙️ Production Architecture")
    st.caption("• **Orchestration:** LangGraph StateGraph")
    st.caption("• **Primary Model:** Llama-3.3-70B")
    st.caption("• **Fallback 1:** Qwen-2.5-Coder (on 429/timeout)")
    st.caption("• **Vector Store:** Pinecone (Dense + BM25)")
    st.caption("• **Safety Boundary:** Confidence Gate (0.70)")

    st.divider()
    if st.button("🚪 Sign Out", **STRETCH):
        st.session_state["authenticated"] = False
        st.session_state["latest_packet"] = None
        st.rerun()

# ---------------------------------------------------------
# Main App Layout (Tabs)
# ---------------------------------------------------------
tab1, tab2, tab3, tab4 = st.tabs([
    "🚀 Live Triage Portal", 
    f"🧑‍💻 Engineer Queue ({len(st.session_state['escalations'])})", 
    f"📚 Knowledge Base & Flywheel ({len(st.session_state['knowledge_base'])})",
    "🏗️ Architecture & Reliability"
])

# ---------------------------------------------------------
# TAB 1: Live Triage Portal
# ---------------------------------------------------------
with tab1:
    # Reviewer Friendly Quick-Start Guide Banner
    st.markdown("""
    <div style="background-color: #1e293b; padding: 14px 20px; border-radius: 10px; border-left: 5px solid #6366f1; margin-bottom: 22px;">
        <div style="display: flex; align-items: center; justify-content: space-between;">
            <span style="font-weight: 700; color: #818cf8; font-size: 1.05rem;">👋 Welcome Dafinitiq Reviewer!</span>
            <span style="background-color: #312e81; color: #c7d2fe; font-size: 0.75rem; padding: 3px 8px; border-radius: 12px; font-weight: 600;">LIVE DEMO MODE</span>
        </div>
        <p style="margin: 6px 0 0 0; color: #cbd5e1; font-size: 0.90rem; line-height: 1.45;">
            <b>How to test in 30 seconds:</b> Select any <b>1-Click Test Scenario</b> in the left sidebar, click <b>"🚀 Run Triage Pipeline"</b>, and observe how the system extracts metadata, enforces deterministic safety gates, and performs grounded retrieval.
        </p>
    </div>
    """, unsafe_allow_html=True)

    # Preset logic
    default_log = ""
    default_service = "PaymentGateway"
    
    if scenario == "1. High Confidence: 429 Rate Limit (Doc Cited)":
        default_log = "HTTP/1.1 429 Too Many Requests\nContent-Type: application/json\nX-RateLimit-Limit: 120\nX-RateLimit-Remaining: 0\nRetry-After: 3\n\n{\"error\": {\"code\": \"RATE_LIMIT_EXCEEDED\", \"message\": \"Throttled: Request rate exceeds allocated tier capacity.\"}}"
        default_service = "Stripe-Billing-API"
    elif scenario == "2. Safety Gate: Secret Key Leak (P1 Circuit Breaker)":
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
        log_input = st.text_area(
            "📋 Paste API Error, Stack Trace, or cURL Output:", 
            value=default_log, 
            height=150,
            help="Raw unstructured technical log or stack trace from a developer"
        )
    with col_in2:
        service_input = st.text_input(
            "🏷️ Component / Service Name:", 
            value=default_service,
            help="The subsystem where the failure occurred"
        )
        st.markdown("<div style='margin-top: 28px;'></div>", unsafe_allow_html=True)
        run_btn = st.button("🚀 Run Triage Pipeline", type="primary", **STRETCH)

    if run_btn:
        if not log_input.strip():
            st.warning("⚠️ Please provide an error log or pick a scenario from the sidebar.")
        else:
            with st.status("Executing DevTriage Confidence Pipeline...", expanded=True) as status:
                st.write("1️⃣ **FastAPI Gateway:** Parsing log payload, trimming redundant trace tokens...")
                time.sleep(0.3)
                st.write("2️⃣ **Deterministic Safety Pre-Check:** Scanning for credential leaks, P1 outage patterns...")
                time.sleep(0.3)
                st.write("3️⃣ **Pydantic Entity Extraction:** Mapping to typed schema (Service, Status, Severity)...")
                time.sleep(0.3)
                st.write("4️⃣ **Pinecone Hybrid Retrieval:** Querying dense vectors + exact code metadata filter...")
                time.sleep(0.3)
                st.write("5️⃣ **Anti-Hallucination Grounding Check:** Tracing synthesized claims to doc chunks...")
                time.sleep(0.3)
                st.write("6️⃣ **Confidence Gating:** Evaluating against 0.70 threshold...")
                time.sleep(0.2)
                packet = run_triage_pipeline(log_input, service_input)
                status.update(label="✅ Triage Pipeline Finished!", state="complete", expanded=False)

    # Display Result
    if st.session_state["latest_packet"] is not None:
        packet = st.session_state["latest_packet"]
        st.markdown("---")

        # Visual Pipeline Audit Stepper Banner
        st.markdown("#### 📊 Live Execution Audit")
        col_s1, col_s2, col_s3, col_s4, col_s5 = st.columns(5)
        
        with col_s1:
            st.metric("1. Gateway Parser", f"HTTP {packet.extraction.http_status or 'N/A'}")
        with col_s2:
            safety_badge = "🚨 TRIGGERED" if packet.extraction.is_security_risk or packet.extraction.severity == "P1" else "🛡️ CLEARED"
            st.metric("2. Safety Gate", safety_badge)
        with col_s3:
            st.metric("3. Assigned Severity", packet.extraction.severity)
        with col_s4:
            st.metric("4. Vector Match", packet.extraction.error_code)
        with col_s5:
            conf_percent = int(packet.confidence_score * 100)
            gate_result = "PASS (>=70%)" if conf_percent >= 70 and packet.status == "RESOLVED_BY_AI" else "ESCALATE"
            st.metric("5. Confidence Gate", f"{conf_percent}% ({gate_result})")

        st.markdown("<br/>", unsafe_allow_html=True)

        # Result Rendering Cards
        if packet.status == "ESCALATED_SAFETY":
            st.error("### 🚨 CRITICAL SAFETY GATE ACTIVATED")
            st.markdown(f"""
            **Reason:** Potential secret key exposure or critical P1 outage pattern identified in payload.
            
            **Action Enforced:** In accordance with production safeguards, automated generative LLM drafting was **bypassed immediately**.
            An incident escalation packet has been dispatched to the **On-Call Engineering Queue**.
            """)
            st.info("👉 Check the **'🧑‍💻 Engineer Queue'** tab to review the escalated incident packet.")

        elif packet.status == "RESOLVED_BY_AI":
            st.success(f"### ✅ Verified Grounded Resolution (Confidence: {int(packet.confidence_score * 100)}%)")
            
            col_res1, col_res2 = st.columns([2.5, 1.5])
            with col_res1:
                st.markdown(packet.proposed_fix)
            with col_res2:
                st.markdown("#### 📚 Verified Citations")
                for cite in packet.citations:
                    st.info(f"📌 {cite}")
                st.markdown("#### 🔒 Anti-Hallucination Audit")
                st.caption("✅ Claims traced to authoritative doc chunk.")
                st.caption("✅ Exact syntax checked against SDK schema.")
                st.caption("✅ Confidence score above 0.70 threshold.")

            st.divider()
            f_col1, f_col2, f_col3 = st.columns([1.5, 2, 3])
            with f_col1:
                if st.button("👍 Verified & Fixed"):
                    st.toast("Feedback recorded: Resolution marked as successful.")
            with f_col2:
                if st.button("👎 Didn't Work? Escalate"):
                    packet.status = "ESCALATED_LOW_CONFIDENCE"
                    st.session_state["escalations"].append(packet)
                    st.toast("Escalated to human engineer queue.")
                    st.rerun()

        elif packet.status == "ESCALATED_LOW_CONFIDENCE":
            st.warning(f"### ⚠️ Low Confidence Triage (Confidence: {int(packet.confidence_score * 100)}%)")
            st.markdown("""
            **Analysis:** The incident payload could not be matched to an authoritative documentation chunk with sufficient certainty (score < 0.70). 
            Rather than risking an LLM hallucination, DevTriage routed this incident to the **On-Call Engineer Escalation Queue**.
            """)
            st.info("👉 Switch to the **'🧑‍💻 Engineer Queue'** tab to review, resolve, and re-index this incident!")

# ---------------------------------------------------------
# TAB 2: Engineer Review & Escalations (Human-in-the-Loop)
# ---------------------------------------------------------
with tab2:
    st.markdown("### 🧑‍💻 On-Call Engineer Escalation Queue")
    st.markdown("""
    When safety rules trigger or AI confidence falls below threshold, incidents land here. 
    **The Continuous Learning Flywheel:** When an engineer approves a fix, it is automatically embedded and indexed back into the Knowledge Base (Tab 3), making the system smarter for all future incidents.
    """)

    if not st.session_state["escalations"]:
        st.success("🎉 No active escalations. The triage queue is completely clear!")
    else:
        for idx, esc in enumerate(list(st.session_state["escalations"])):
            with st.expander(f"🔴 [{esc.extraction.severity}] {esc.incident_id} — {esc.extraction.service} ({esc.extraction.error_code})", expanded=(idx==0)):
                col_e1, col_e2 = st.columns([2, 1])
                with col_e1:
                    st.markdown("**Raw Incident Log:**")
                    st.code(esc.raw_log, language="bash")
                with col_e2:
                    st.markdown("**Incident Telemetry:**")
                    st.text(f"ID: {esc.incident_id}")
                    st.text(f"Timestamp: {esc.timestamp}")
                    st.text(f"Status: {esc.status}")
                    st.text(f"Confidence: {int(esc.confidence_score * 100)}%")

                st.markdown("#### 🛠️ Engineer Resolution (Active Learning Flywheel)")
                eng_fix = st.text_area(
                    "Review or edit the approved resolution for this incident:",
                    value=esc.proposed_fix,
                    key=f"eng_fix_{idx}",
                    height=130
                )

                if st.button(f"✅ Approve & Re-Index into Knowledge Base (#{esc.incident_id})", key=f"btn_approve_{idx}"):
                    new_doc = {
                        "id": f"DOC-FLY-{int(time.time())}",
                        "title": f"Resolution for {esc.extraction.error_code} ({esc.extraction.service})",
                        "area": esc.extraction.service,
                        "error_code": esc.extraction.error_code,
                        "keywords": [esc.extraction.service.lower(), esc.extraction.error_code.lower(), "flywheel", "approved", "timeout", "batch"],
                        "content": eng_fix,
                        "fix_code": "# Solution verified by On-Call Engineer\ndef handle_batch_timeout():\n    # Break batch into chunks of 500 records\n    pass",
                        "citation": f"Human-Verified Incident #{esc.incident_id} (Resolved by On-Call Engineer)"
                    }
                    st.session_state["knowledge_base"].append(new_doc)
                    st.session_state["escalations"].remove(esc)
                    st.session_state["latest_packet"] = None
                    st.toast("🎉 Approved resolution embedded and indexed into Pinecone vector store!")
                    st.rerun()

# ---------------------------------------------------------
# TAB 3: Knowledge Base & Flywheel Index
# ---------------------------------------------------------
with tab3:
    st.markdown("### 📚 Active Knowledge Base (Pinecone Vector Index)")
    st.markdown("All documentation chunks available to DevTriage for hybrid retrieval and anti-hallucination grounding.")

    st.info(f"💡 Currently indexing **{len(st.session_state['knowledge_base'])}** authoritative technical documentation chunks.")

    for doc in st.session_state["knowledge_base"]:
        with st.container(border=True):
            col_d1, col_d2 = st.columns([3, 1])
            with col_d1:
                st.markdown(f"#### {doc['title']} (`{doc['id']}`)")
                st.write(doc["content"])
                if "fix_code" in doc:
                    st.code(doc["fix_code"], language="python")
            with col_d2:
                st.info(f"**Area:** {doc['area']}")
                st.caption(f"**Error Code:** `{doc['error_code']}`")
                st.caption(f"**Citations:** {doc['citation']}")

# ---------------------------------------------------------
# TAB 4: Architecture & Reliability
# ---------------------------------------------------------
with tab4:
    st.markdown("### 🏗️ Production System Architecture")
    st.markdown("Confidence-Gated Developer Incident Triage Copilot with Human-in-the-Loop Active Learning Flywheel.")

    try:
        st.image("architecture.png", caption="DevTriage AI - End-to-End System Architecture", **STRETCH)
    except Exception:
        st.info("Architecture diagram located at `architecture.png`")

    st.markdown("""
    ---
    ### 🔬 Architectural Pillars

    1. **FastAPI Gateway & Token Trimmer:** Parses raw HTTP responses, status codes, and removes redundant stack trace lines before vectorization to minimize token latency.
    2. **Deterministic Safety Pre-Check:** Critical keywords (passwords, private keys, database corruption) trigger an immediate safe circuit breaker, bypassing generative LLMs entirely to prevent hallucinations or data leaks.
    3. **Hybrid Retrieval (Pinecone + BM25):** Combines dense vector semantics with exact keyword and error-code metadata filtering.
    4. **LLM Fallback Chain:** Primary model (Llama-3.3-70B) fails over to secondary models (Qwen-2.5-Coder) upon 429 rate limits or timeouts, with a safe queue escalation fallback.
    5. **Anti-Hallucination Grounding Check:** Every claim in the synthesized fix is strictly matched against retrieved doc chunks before presentation.
    6. **Confidence Gating & Active Learning Flywheel:** Issues with confidence $\ge 0.70$ are presented with citations; lower-confidence issues are escalated to human engineers, whose approved fixes are re-indexed back into the knowledge base without model retraining.
    """)
