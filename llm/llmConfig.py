"""Lightweight single-model (llama / Ollama style) LLM client.

Removed Azure OpenAI support per configuration request. Public API retained:
 - AVAILABLE_MODELS (single entry)
 - DEFAULT_MODEL
 - get_llm_response(prompt, system_message, temperature, model)
 - getJSONResponseLLM(prompt, ...)

Environment variables used:
 OLLAMA_API_URL (or OLLAMA_API_BASE), OLLAMA_API_KEY, OLLAMA_MODEL, DEFAULT_MODEL (optional override)
"""

from dotenv import load_dotenv
import os, json
from typing import Dict, Any, Optional, List
import requests
import re

from llm.prompts import THREAT_MODELING_EXPERT_PROMPT

load_dotenv()

# ----------  / Ollama (llama) configuration ----------
OLLAMA_API_URL  = os.getenv("OLLAMA_API_URL", "").strip().rstrip("/")
OLLAMA_API_BASE = os.getenv("OLLAMA_API_BASE", "").strip().rstrip("/")
if not OLLAMA_API_URL:
    if OLLAMA_API_BASE:
        OLLAMA_API_URL = f"{OLLAMA_API_BASE}/api/chat"

OLLAMA_API_KEY = os.getenv("OLLAMA_API_KEY", "").strip()
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1:8b").strip()

# ---------- Model registry (single) ----------
AVAILABLE_MODELS: List[Dict[str, Any]] = [
    {"name": OLLAMA_MODEL, "model": OLLAMA_MODEL, "provider": ""}
]
DEFAULT_MODEL = os.getenv("DEFAULT_MODEL", OLLAMA_MODEL) or OLLAMA_MODEL

# ---------- Internal helpers ----------

def _chat(model_id: str, messages: List[Dict[str, str]]) -> str:
    if not OLLAMA_API_URL or not OLLAMA_API_KEY:
        raise RuntimeError(" LLM configuration missing (OLLAMA_API_URL / OLLAMA_API_KEY)")
    headers = {
        "Authorization": f"Bearer {OLLAMA_API_KEY}",
        "Content-Type": "application/json",
    }
    payload = {"model": model_id, "messages": messages, "stream": False}
    resp = requests.post(OLLAMA_API_URL, headers=headers, json=payload, timeout=300)
    if resp.status_code != 200:
        raise RuntimeError(f"LLM request failed ({resp.status_code}): {resp.text[:600]}")
    data = resp.json()
    if isinstance(data, dict) and "message" in data and isinstance(data["message"], dict) and "content" in data["message"]:
        return data["message"]["content"]
    if "choices" in data:  # fallback if gateway proxies OpenAI schema
        try:
            return data["choices"][0]["message"]["content"]
        except Exception:
            pass
    raise RuntimeError(f"Unexpected  response schema: {json.dumps(data)[:800]}")

# ---------- Public API ----------

def get_llm_response(
    prompt: str,
    system_message: Optional[str] = None,
    temperature: float = 0.7,
    model: Optional[str] = None
) -> str:
    """Send a prompt to the (single) configured llama model."""
    model_id = OLLAMA_MODEL  # ignore external model parameter now

    messages: List[Dict[str, str]] = []
    if system_message:
        messages.append({"role": "system", "content": system_message})
    messages.append({"role": "user", "content": prompt})

    return _chat(model_id, messages)

# ---------- JSON extraction helpers (unchanged approach) ----------

def _try_load_json_from_text(text: str) -> Optional[Dict[str, Any]]:
    t = text.strip()
    if t.startswith("{") and "}" in t:
        try:
            return json.loads(t[: t.rfind("}") + 1])
        except Exception:
            pass
    if "```json" in text:
        try:
            chunk = text.split("```json", 1)[1]
            if "```" in chunk:
                chunk = chunk.split("```", 1)[0]
            if "}" in chunk:
                chunk = chunk[: chunk.rfind("}") + 1]
            return json.loads(chunk.strip())
        except Exception:
            pass
    s = text.find("{")
    if s != -1:
        depth = 0; end = -1
        for i, ch in enumerate(text[s:], start=s):
            if ch == "{": depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = i; break
        if end != -1:
            try:
                return json.loads(text[s:end+1])
            except Exception:
                pass
    return None

# ---------- Utility: GitHub account extraction ----------
_GITHUB_URL_RE = re.compile(r"https?://github\.com/([A-Za-z0-9_.-]+)(?:/([A-Za-z0-9_.-]+))?", re.IGNORECASE)

def extract_github_accounts(text: str) -> List[str]:
    """Extract unique GitHub account/organization (first path segment) names from arbitrary text."""
    if not text:
        return []
    owners = {m.group(1) for m in _GITHUB_URL_RE.finditer(text)}
    return sorted(owners)

def getJSONResponseLLM(
    prompt: str,
    temperature: float = 0.7,
    model: Optional[str] = None
) -> Dict[str, Any]:
    """
    Completeness check requesting STRICT JSON.
    Falls back to a permissive default on parse failure.
    Additionally augments response with detected GitHub account owners (github_accounts).
    """
    completeness_prompt = (
        f"Application Description:\n\n{prompt}\n\n"
        "Is this description detailed enough for STRIDE threat modeling? "
        "Respond in STRICT JSON ONLY with fields: "
        '{"complete":"yes"|"no","feedback":[<missing detail strings>]}'
    )
    text = get_llm_response(
        prompt=completeness_prompt,
        system_message=THREAT_MODELING_EXPERT_PROMPT,
        temperature=temperature,
        model=model
    )
    parsed = _try_load_json_from_text(text) or {"complete": "yes", "feedback": []}
    # Inject github account info (non-breaking addition)
    parsed["github_accounts"] = extract_github_accounts(prompt)
    return parsed
