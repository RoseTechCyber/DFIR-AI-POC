"""
Unified DFIR AI Investigator
Day 2: Identification and Preservation
Day 3: Timeline and Correlation

The original api-day2.py and api.py remain independently runnable.
This module provides a unified website for local testing.
"""

import importlib.util
import logging
import sys
from pathlib import Path

from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse, JSONResponse

BASE_DIR = Path(__file__).resolve().parent

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("dfir.main")


# ------------------------------------------------------------
# LOAD EXISTING APPLICATIONS
# ------------------------------------------------------------

def load_python_module(module_name: str, filename: str):
    """Load an existing Python file as a module."""

    module_path = BASE_DIR / filename

    if not module_path.is_file():
        raise FileNotFoundError(
            f"Required application file not found: {module_path}"
        )

    spec = importlib.util.spec_from_file_location(
        module_name,
        module_path,
    )

    if spec is None or spec.loader is None:
        raise ImportError(
            f"Unable to load module from {module_path}"
        )

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)

    return module


# Load the original implementations without copying their logic.
day2_module = load_python_module(
    "dfir_day2_legacy",
    "api-day2.py",
)

day3_module = load_python_module(
    "dfir_day3_legacy",
    "api.py",
)


# ------------------------------------------------------------
# UNIFIED FASTAPI APPLICATION
# ------------------------------------------------------------

app = FastAPI(
    title="DFIR AI Investigator",
    description=(
        "Unified digital-forensics laboratory: "
        "Day 2 Identification and Preservation; "
        "Day 3 Timeline and Correlation."
    ),
    version="1.0.0",
)


# ------------------------------------------------------------
# SHARED HOMEPAGE
# ------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport"
              content="width=device-width, initial-scale=1">

        <title>DFIR AI Investigator</title>

        <style>
            body {
                font-family: Arial, sans-serif;
                max-width: 1000px;
                margin: 40px auto;
                padding: 20px;
                background: #f4f6f8;
                color: #222;
                line-height: 1.6;
            }

            .card {
                background: white;
                padding: 28px;
                border-radius: 12px;
                box-shadow: 0 2px 10px #ddd;
                margin-bottom: 24px;
            }

            h1, h2 {
                color: #17365d;
            }

            .intro {
                background: #eef5ff;
                border-left: 5px solid #3778c2;
                padding: 16px;
                margin-bottom: 24px;
            }

            .modules {
                display: grid;
                grid-template-columns:
                    repeat(auto-fit, minmax(260px, 1fr));
                gap: 20px;
            }

            .module {
                border: 1px solid #dce2e8;
                border-radius: 10px;
                padding: 22px;
            }

            .module a {
                display: inline-block;
                background: #17365d;
                color: white;
                padding: 12px 20px;
                border-radius: 6px;
                text-decoration: none;
                margin-top: 10px;
            }

            .module a:hover {
                background: #0f2744;
            }

            .note {
                color: #555;
                font-size: 14px;
            }

            footer {
                margin-top: 25px;
                color: #666;
                font-size: 13px;
            }
        </style>
    </head>

    <body>
        <div class="card">
            <h1>DFIR AI Investigator</h1>

            <div class="intro">
                <strong>AI-assisted digital forensics laboratory</strong>
                <p>
                    Explore the forensic investigation lifecycle
                    through separate modules in one unified application.
                </p>
                <p>
                    AI-generated assessments are advisory.
                    Forensic conclusions must be verified against
                    the underlying evidence.
                </p>
            </div>

            <h2>Investigation Modules</h2>

            <div class="modules">
                <div class="module">
                    <h2>Day 2</h2>
                    <h3>Identification and Preservation</h3>
                    <p>
                        Review the supplied evidence, examine
                        preliminary findings, and understand the
                        importance of evidence integrity.
                    </p>
                    <a href="/day2">Open Day 2</a>
                </div>

                <div class="module">
                    <h2>Day 3</h2>
                    <h3>Timeline and Correlation</h3>
                    <p>
                        Explore chronological events, examine
                        temporal correlations, and generate a
                        preliminary AI-assisted assessment.
                    </p>
                    <a href="/day3">Open Day 3</a>
                </div>
            </div>

            <footer>
                DFIR AI Investigator | Unified demonstration
            </footer>
        </div>
    </body>
    </html>
    """


# ------------------------------------------------------------
# DAY 2 — IDENTIFICATION AND PRESERVATION
# ------------------------------------------------------------

def day2_home_html():
    """
    Reuse the existing Day 2 homepage.

    Its form originally posts to /analyze.
    Rewrite that action for the unified URL.
    """

    content = day2_module.home()

    content = content.replace(
        'action="/analyze"',
        'action="/day2/analyze"',
    )

    return content


@app.get("/day2", response_class=HTMLResponse)
@app.get("/day2/", response_class=HTMLResponse)
def day2_home():
    return HTMLResponse(content=day2_home_html())


@app.post("/day2/analyze", response_class=HTMLResponse)
def day2_analyze(question: str = Form(...)):
    # Reuse the original Day 2 analysis function.
    return HTMLResponse(
        content=day2_module.analyze(question)
    )


@app.get("/day2/health")
def day2_health():
    return day2_module.health()


# ------------------------------------------------------------
# DAY 3 — TIMELINE AND CORRELATION
# ------------------------------------------------------------

def day3_home_html():
    """Reuse the existing Day 3 homepage with prefixed links."""

    content = day3_module.home()

    content = content.replace(
        'action="/analyze"',
        'action="/day3/analyze"',
    )

    content = content.replace(
        'href="/health"',
        'href="/day3/health"',
    )

    content = content.replace(
        'href="/case/',
        'href="/day3/case/',
    )

    return content


@app.get("/day3", response_class=HTMLResponse)
@app.get("/day3/", response_class=HTMLResponse)
def day3_home():
    return HTMLResponse(content=day3_home_html())


@app.post("/day3/analyze", response_class=HTMLResponse)
def day3_analyze(question: str = Form(...)):
    # Reuse the original Day 3 analysis function.
    return HTMLResponse(
        content=day3_module.analyze(question)
    )


@app.get("/day3/health")
def day3_health():
    return day3_module.health()


@app.get("/day3/case/{case_id}/timeline")
def day3_timeline(case_id: str):
    return day3_module.case_timeline(case_id)


@app.get("/day3/case/{case_id}/correlations")
def day3_correlations(case_id: str):
    return day3_module.case_correlations(case_id)


# ------------------------------------------------------------
# UNIFIED HEALTH ENDPOINT
# ------------------------------------------------------------

@app.get("/health")
def health():
    return {
        "status": "ok",
        "application": "DFIR AI Investigator",
        "version": app.version,
        "modules": {
            "day2": {
                "name": "Identification and Preservation",
                "url": "/day2",
                "health_url": "/day2/health",
            },
            "day3": {
                "name": "Timeline and Correlation",
                "url": "/day3",
                "health_url": "/day3/health",
            },
        },
    }


# ------------------------------------------------------------
# RUN WITH:
# python -m uvicorn main:app --host 127.0.0.1 --port 8002
# ------------------------------------------------------------