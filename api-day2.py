from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse
from pathlib import Path
from urllib.request import Request, urlopen
import json
import html
import os

app = FastAPI(title="DFIR AI Investigator")

BASE_DIR = Path(__file__).resolve().parent

EVIDENCE_FILE = Path(
    os.getenv(
        "DFIR_DAY2_EVIDENCE_FILE",
        str(BASE_DIR / "evidence.txt"),
    )
)
RESULT_FILE = Path(r"C:\DFIR-POC\day2_result.txt")

OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
MODEL = "qwen2.5:0.5b"


def load_evidence():
    if not EVIDENCE_FILE.exists():
        return "No evidence file was found."

    return EVIDENCE_FILE.read_text(encoding="utf-8")


def analyze_with_ollama(question, evidence):
    prompt = f"""
```text
You are an AI assistant supporting a digital-forensics investigator.

Your task is to provide a concise preliminary assessment of the supplied evidence.

STRICT FORENSIC RULES:
1. Analyze ONLY the supplied evidence.
2. Never invent facts, events, artifacts, timestamps, or files.
3. Do not confuse temporal correlation with proof of an action.
4. A USB connection followed by file access does NOT prove that a file was copied.
5. A file copy should only be treated as directly supported when the evidence contains a copy event, destination-file evidence, matching hashes, or another explicit transfer indicator.
6. If direct copy evidence is absent, clearly state that the copy is NOT PROVEN.
7. Explain your reasoning briefly.
8. Do not use excessive confidence.

Return exactly these sections:

PRELIMINARY FINDING:
EVIDENCE OBSERVED:
REASONING:
CONFIDENCE:
LIMITATION:
RECOMMENDED NEXT STEP:

QUESTION:
{question}

EVIDENCE:
{evidence}
```

"""

    payload = {
        "model": MODEL,
        "prompt": prompt,
        "stream": False
    }

    data = json.dumps(payload).encode("utf-8")

    request = Request(
        OLLAMA_URL,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    with urlopen(request, timeout=120) as response:
        result = json.loads(response.read().decode("utf-8"))

    return result.get("response", "No response returned by Ollama.")


def validate_forensic_finding(question, evidence, ai_response):
    """
    Deterministic validation layer.

    For this Day 2 PoC, the supplied evidence contains:
    - USB connection
    - file access
    - USB disconnection

    It does NOT contain a direct copy event.

    Therefore, the final system finding must not claim that the file
    was proven to have been copied.
    """

    evidence_lower = evidence.lower()

    direct_copy_indicators = [
        "file copied",
        "copy operation",
        "copy event",
        "copied to usb",
        "destination file",
        "matching hash"
    ]

    has_direct_copy_evidence = any(
        indicator in evidence_lower
        for indicator in direct_copy_indicators
    )

    if has_direct_copy_evidence:
        finding = "Evidence contains an indicator of a direct copy operation."
        confidence = "Requires investigator review"
        assessment = (
            "The supplied evidence contains a direct-copy indicator. "
            "The investigator should verify the underlying artifact before "
            "treating the transfer as established."
        )
        limitation = (
            "The AI-generated assessment is preliminary and should be "
            "verified against the original forensic artifact."
        )
    else:
        finding = "NOT PROVEN"
        confidence = "LOW–MEDIUM"
        assessment = (
            "The evidence establishes that a USB storage device was connected "
            "while the specified file was accessed. However, the supplied "
            "evidence contains no direct copy event, destination-file evidence, "
            "matching hash, or other explicit indicator proving that the file "
            "was copied to the USB device."
        )
        limitation = (
            "The available evidence establishes temporal correlation but does "
            "not establish that a file-transfer operation occurred."
        )

    next_step = (
        "Examine USB filesystem artifacts, file-copy events, destination-file "
        "metadata, timestamps, and hashes for direct evidence of a transfer."
    )

    return {
        "finding": finding,
        "confidence": confidence,
        "assessment": assessment,
        "limitation": limitation,
        "next_step": next_step,
        "direct_copy_evidence": has_direct_copy_evidence
    }


@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>DFIR AI Investigator</title>

        <style>
            body {
                font-family: Arial, sans-serif;
                max-width: 950px;
                margin: 40px auto;
                padding: 20px;
                background: #f4f6f8;
                color: #222;
            }

            .card {
                background: white;
                padding: 28px;
                border-radius: 12px;
                box-shadow: 0 2px 10px #ccc;
                margin-bottom: 20px;
            }

            h1 {
                color: #17365d;
            }

            textarea {
                width: 100%;
                min-height: 140px;
                padding: 12px;
                margin-top: 8px;
                margin-bottom: 18px;
                box-sizing: border-box;
                border: 1px solid #bbb;
                border-radius: 6px;
                font-size: 15px;
            }

            button {
                background: #17365d;
                color: white;
                padding: 13px 28px;
                border: none;
                border-radius: 6px;
                cursor: pointer;
                font-size: 15px;
            }

            button:hover {
                background: #0f2744;
            }

            .info {
                background: #eef5ff;
                border-left: 5px solid #3778c2;
                padding: 14px;
                margin-bottom: 20px;
            }

            .warning {
                background: #fff4e5;
                border-left: 5px solid #e69500;
                padding: 14px;
                margin-bottom: 20px;
            }

            pre {
                white-space: pre-wrap;
                background: #f0f2f5;
                padding: 20px;
                border-radius: 8px;
                line-height: 1.5;
            }

            .finding {
                background: #fff0f0;
                border-left: 6px solid #c62828;
                padding: 18px;
                font-size: 20px;
                font-weight: bold;
                margin-bottom: 20px;
            }

            .confidence {
                display: inline-block;
                background: #eee;
                padding: 7px 12px;
                border-radius: 5px;
                font-weight: bold;
            }

            a {
                color: #17365d;
                text-decoration: none;
            }
        </style>
    </head>

    <body>

        <div class="card">

            <h1>DFIR AI Investigator</h1>

            <div class="info">
                <strong>AI-assisted forensic analysis</strong><br>
                The system uses a local AI model to generate a preliminary
                assessment and applies evidence-grounding rules before
                presenting the final finding.
            </div>

            <form method="post" action="/analyze">

                <label>
                    <strong>Investigator Question</strong>
                </label>

                <textarea name="question" required>Does this evidence prove that Confidential_Project_Report.docx was copied to the USB device?</textarea>

                <button type="submit">
                    Analyze Evidence
                </button>

            </form>

        </div>

    </body>
    </html>
    """


@app.post("/analyze", response_class=HTMLResponse)
def analyze(question: str = Form(...)):

    evidence = load_evidence()

    try:
        ai_response = analyze_with_ollama(
            question,
            evidence
        )

        validation = validate_forensic_finding(
            question,
            evidence,
            ai_response
        )

        final_result = f"""
FINAL FORENSIC FINDING
======================

FINDING:
{validation["finding"]}

CONFIDENCE:
{validation["confidence"]}

EVIDENCE-BASED ASSESSMENT:
{validation["assessment"]}

LIMITATION:
{validation["limitation"]}

NEXT FORENSIC STEP:
{validation["next_step"]}


AI PRELIMINARY ASSESSMENT
=========================

{ai_response}


VALIDATION
==========

Direct copy evidence detected:
{validation["direct_copy_evidence"]}

The final finding is generated by applying deterministic
evidence-grounding rules to the supplied forensic evidence.
"""

        RESULT_FILE.write_text(
            final_result,
            encoding="utf-8"
        )

        safe_question = html.escape(question)
        safe_result = html.escape(final_result)

        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>DFIR Finding</title>

            <style>
                body {{
                    font-family: Arial, sans-serif;
                    max-width: 950px;
                    margin: 40px auto;
                    padding: 20px;
                    background: #f4f6f8;
                    color: #222;
                }}

                .card {{
                    background: white;
                    padding: 28px;
                    border-radius: 12px;
                    box-shadow: 0 2px 10px #ccc;
                }}

                .finding {{
                    background: #fff0f0;
                    border-left: 6px solid #c62828;
                    padding: 18px;
                    font-size: 22px;
                    font-weight: bold;
                    margin: 20px 0;
                }}

                .validated {{
                    background: #eef8ee;
                    border-left: 6px solid #2e7d32;
                    padding: 18px;
                    margin: 20px 0;
                }}

                pre {{
                    white-space: pre-wrap;
                    background: #f0f2f5;
                    padding: 20px;
                    border-radius: 8px;
                    line-height: 1.5;
                }}

                a {{
                    display: inline-block;
                    margin-top: 20px;
                    color: #17365d;
                }}
            </style>
        </head>

        <body>

            <div class="card">

                <h1>AI Forensic Finding</h1>

                <p>
                    <strong>Question:</strong>
                </p>

                <p>{safe_question}</p>

                <div class="finding">
                    FINAL FINDING: {html.escape(validation["finding"])}
                </div>

                <div class="validated">
                    <strong>Evidence-grounded validation applied.</strong><br>
                    The AI response was treated as a preliminary assessment,
                    not as the final forensic authority.
                </div>

                <h2>Validated Result</h2>

                <pre>{safe_result}</pre>

                <a href="/">
                    ← New investigation
                </a>

            </div>

        </body>
        </html>
        """

    except Exception as error:

        error_result = f"""
AI analysis failed.

Error:
{error}
"""

        RESULT_FILE.write_text(
            error_result,
            encoding="utf-8"
        )

        return f"""
        <h1>Analysis Error</h1>
        <pre>{html.escape(error_result)}</pre>
        <a href="/">← Return</a>
        """


@app.get("/health")
def health():
    return {
        "status": "ok",
        "model": MODEL,
        "ollama": OLLAMA_URL,
        "evidence_file": str(EVIDENCE_FILE)
    }
