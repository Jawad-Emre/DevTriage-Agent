# 🛡️ DevTriage Agent
**Autonomous, Confidence-Gated API Incident & Developer Triage Copilot**

DevTriage Agent is an enterprise-grade incident copilot built for backend engineers and Developer Experience (DevEx) teams. When developers encounter cryptic stack traces, 4xx/5xx API responses, or webhook delivery failures, DevTriage diagnoses the issue against authoritative documentation with deterministic safety gating and an active learning feedback loop.

---

## 🌟 Key Features

1. **Deterministic Safety Pre-Check:** Automatically suppresses automated LLM generation for P1 outages, credential exposures, or high-risk billing failures, preventing hallucinations on high-stakes incidents.
2. **Pydantic Entity Extraction:** Parses unstructured stack traces into normalized schemas (service, HTTP status, severity, error code).
3. **Hybrid Retrieval (Pinecone + BM25):** Dense vector search paired with exact keyword and error-code metadata filtering.
4. **LLM Fallback Chain:** Circuit-breaker resilience (Primary: Llama-3.3-70B $\to$ Fallback 1: Qwen-2.5-Coder $\to$ Safe Escalation) to handle provider 429 rate limits or timeouts.
5. **Anti-Hallucination Grounding Check:** Traces every claim in the proposed resolution to indexed documentation chunks.
6. **Confidence Gating & Human-in-the-Loop Flywheel:** Issues scoring below threshold ($\ge 0.70$) route to an On-Call Engineer queue. Approved resolutions are re-indexed back into the knowledge base.

---

## 🏗️ Architecture Diagram

![DevTriage Architecture](architecture.png)

```mermaid
flowchart TD
    classDef agent fill:#EEF2FF,stroke:#6366F1,stroke-width:1.5px,color:#1E1B4B;
    classDef external fill:#ECFDF5,stroke:#10B981,stroke-width:1.5px,color:#064E3B;
    classDef human fill:#FFF7ED,stroke:#F97316,stroke-width:1.5px,color:#7C2D12;
    classDef ui fill:#F4F4F5,stroke:#A1A1AA,stroke-width:1.5px,color:#18181B;

    subgraph SETUP ["Setup, once per company"]
        D1["<b>Company docs</b><br/>Markdown pages"]:::ui
        D2["<b>Chunk + tags</b><br/>Error code, area"]:::ui
        D3["<b>Embed docs</b><br/>Same open model"]:::external
        D4[("<b>Pinecone index</b><br/>Vectors + metadata")]:::external
        D1 --> D2 --> D3 --> D4
    end

    U["<b>User portal</b><br/>Error, log or curl"]:::ui
    GW["<b>FastAPI gateway</b><br/>Regex log parser"]:::ui
    SP{"<b>Safety pre-check</b><br/>Critical keyword rules"}:::agent
    EXT["<b>Extract + severity</b><br/>Pydantic, LLM chain"]:::agent
    EQ["<b>Embed query</b><br/>Open model, OpenRouter"]:::external
    PS["<b>Pinecone search</b><br/>Top-k + code filter"]:::external
    DF["<b>Draft cited fix</b><br/>Uses LLM chain"]:::agent
    GC["<b>Grounding check</b><br/>Claims vs chunks"]:::agent
    CG{"<b>Confidence gate</b><br/>Threshold + P1/P2 rule"}:::agent
    ANS["<b>Cited fix to user</b><br/>Not helped? Escalate"]:::ui

    subgraph LLM_CHAIN ["LLM fallback chain"]
        MA["<b>Model A</b><br/>Primary"]
        MB["<b>Model B</b><br/>Fallback 1"]
        MC["<b>Model C</b><br/>Fallback 2"]
        MSAFE["<b>Safe fallback</b><br/>Queue + escalate"]
        MA -->|429 / timeout| MB
        MB -->|429 / timeout| MC
        MC -->|all failed| MSAFE
    end

    ESC["<b>Escalation packet</b><br/>Card + docs checked"]:::human
    REV["<b>Engineer reviews</b><br/>Approves or edits"]:::human
    REIDX["<b>Re-index fix</b><br/>Embed + upsert"]:::human

    U --> GW --> SP
    SP -->|yes| ESC
    SP -->|no| EXT
    EXT --> EQ --> PS
    D4 -.->|search| PS
    PS --> DF --> GC --> CG
    CG -->|high| ANS
    CG -->|low| ESC
    ANS -.->|not helped| ESC
    ESC --> REV --> REIDX
    REIDX -.->|approved fixes re-indexed| D4

    EXT -.-> MA
    DF -.-> MA
    GC -.-> MA
```

---

## 🚀 Quickstart & Local Execution

### 1. Clone Repository
```bash
git clone https://github.com/Jawad-Emre/DevTriage-Agent.git
cd DevTriage-Agent
```

### 2. Install Dependencies
```bash
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Launch App
```bash
streamlit run app.py
```

---

## 🔑 Demo Access Credentials
* **Email:** `demo@company.com`
* **Password:** `triage2026`
*(Or click the 1-Click Instant Demo Login button on the landing screen)*
