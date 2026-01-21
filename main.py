"""
Core functionality for the AI Agent for Threat Modeling.
Provides threat modeling analysis functions used by the web application.
"""

import json
from typing import Dict, List, Any
import time
import traceback

from llm import llmConfig
from system_architecture import system_analyzer, whitebox_analyzer
from threat_model import stride_analyzer
from threat_model import retryable
from code_scan.scanner import run_combined_scan


TIMEOUT_MARKERS = ["504", "gateway time-out", "gateway timeout", "timed out", "timeout"]
SERVER_BUSY_MARKERS = ["503", "server busy", "maximum pending requests"]

def _is_timeout(err: Exception) -> bool:
    msg = str(err).lower()
    return any(m in msg for m in TIMEOUT_MARKERS)


def _is_server_busy(err: Exception) -> bool:
    msg = str(err).lower()
    return any(m in msg for m in SERVER_BUSY_MARKERS)


def perform_whitebox_analysis(code_dir: str, model: str = None) -> Dict[str, Any]:
    """Perform whitebox analysis on a code directory."""
    try:
        # Extract architecture from source code
        architecture_init = whitebox_analyzer.get_whitebox_architecture(code_dir)
        if not architecture_init or "components" not in architecture_init:
            raise ValueError("Whitebox analysis did not produce a valid architecture JSON.")

        analyzed_architecture = system_analyzer.get_system_architecture(architecture_init, model=model)

        # Run STRIDE analysis with retry logic for server busy errors
        threats = retryable.analyze_threats_parallel_with_retry(analyzed_architecture, model=model)

        # Run local SAST scans (Bandit + optional Semgrep)
        code_scan = run_combined_scan(code_dir, use_semgrep=True)

        tm = build_threat_model(
            "Analyzed Application (Whitebox)",
            "Architecture auto-discovered from code",
            analyzed_architecture,
            threats
        )
        tm["codeScan"] = code_scan
        return tm
    except Exception as e:
        raise Exception(f"Error during whitebox analysis: {str(e)}")


def _heuristic_completeness(description: str) -> Dict[str, Any]:
    """Lightweight fallback completeness evaluator when LLM check times out."""
    text = (description or '').lower()
    signals = {
        'components': any(k in text for k in ['service', 'api', 'component', 'module', 'lambda', 'microservice', 'frontend', 'gateway']),
        'data_flows': any(k in text for k in ['flow', 'request', 'response', 'sends', 'receives', 'queue', 'stream']),
        'assets': any(k in text for k in ['data', 'pii', 'token', 'secret', 'database', 'db', 'storage', 'bucket']),
        'trust_boundaries': any(k in text for k in ['vpc', 'subnet', 'boundary', 'zone', 'dmz', 'network segment', 'external']),
        'security_controls': any(k in text for k in ['auth', 'encrypt', 'tls', 'https', 'mfa', 'waf', 'iam', 'monitor', 'log'])
    }
    missing = [k for k, present in signals.items() if not present]
    complete = len(missing) <= 2  # tolerate a couple missing to proceed
    return { 'complete': complete, 'missing': missing }


def perform_textual_analysis(description: str, use_parallel: bool = False, model: str = None) -> Dict[str, Any]:
    """Perform textual analysis on an application description."""
    # Robust completeness validation with retry on transient 503/server busy
    max_attempts = 4
    backoff_base = 1.0
    last_error = None
    completeness_check = None
    for attempt in range(1, max_attempts + 1):
        try:
            completeness_check = llmConfig.getJSONResponseLLM(description, model=model)
            break
        except Exception as e:  # Capture transient LLM gateway / busy errors
            err_str = str(e).lower()
            last_error = e
            if '503' in err_str or 'server busy' in err_str or 'maximum pending requests' in err_str:
                if attempt < max_attempts:
                    time.sleep(backoff_base * (2 ** (attempt - 1)))
                    continue
                else:
                    # Fallback to heuristic completeness instead of hard failure
                    heuristic = _heuristic_completeness(description)
                    completeness_check = {
                        "source": "heuristic-fallback",
                        "complete": "yes" if heuristic['complete'] else "no",
                        "feedback": heuristic['missing']
                    }
                    break
            else:
                # Non-transient error: surface immediately
                raise Exception(f"Completeness validation failed: {str(e)}")
    else:  # pragma: no cover (safety)
        if completeness_check is None:
            heuristic = _heuristic_completeness(description)
            completeness_check = {
                "source": "heuristic-fallback-loop-exit",
                "complete": "yes" if heuristic['complete'] else "no",
                "feedback": heuristic['missing']
            }

    if completeness_check.get("complete") == "no":
        feedback = completeness_check.get("feedback", [])
        if isinstance(feedback, list) and feedback:
            raise ValueError(f"More details needed for effective threat modeling: {feedback}")
        else:
            raise ValueError("More details needed for effective threat modeling. Please provide more comprehensive information about your application architecture, data flows, and security mechanisms.")

    try:
        arch = system_analyzer.get_system_architecture(description, model=model)
        if use_parallel:
            threats = retryable.analyze_threats_parallel_with_retry(arch, model=model)
        else:
            threats = retryable.analyze_threats_with_retry(arch, model=model)
        truncated_desc = description[:100] + "..." if len(description) > 100 else description
        return build_threat_model("Analyzed Application", truncated_desc, arch, threats)
    except Exception as e:
        raise Exception(f"Error during textual analysis: {str(e)}")


def build_threat_model(name: str, description: str, architecture: Dict[str, Any], 
                       threats: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "application": {
            "name": name,
            "description": description,
            "owner": "Threat Modeling Tool User"
        },
        "components": architecture.get("components", []),
        "assets": architecture.get("assets", []),
        "dataFlows": architecture.get("dataFlows", []),
        "trustBoundaries": architecture.get("trustBoundaries", []),
        "threats": threats,
    }
