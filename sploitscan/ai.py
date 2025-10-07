"""
AI orchestration: prompt generation and provider routing.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional

from .config import load_config
from .ai_providers.openai_provider import get_openai_risk_assessment
# Other providers (Google/Grok/DeepSeek) are imported lazily inside get_risk_assessment()
# to keep optional dependencies graceful and avoid import errors if packages are not installed.


def generate_ai_prompt(cve_details: str, cve_data: Dict[str, Any]) -> str:
    """
    Build a deterministic, hallucination-resistant prompt. We:
    - Force exactly four numbered sections with strict formatting.
    - Emphasize evidential reasoning using provided data (CVE, KEV, EPSS, exploits).
    - Forbid inventing patches/links and require stating “Unknown” if uncertain.
    - Optimize for security triage usefulness (business impact + concrete actions).
    """
    prompt = f"""
You are a senior security analyst. Using ONLY the information provided below, produce EXACTLY four sections, each starting with the numeric header shown:

1. Risk Assessment
Explain: vulnerability nature, affected components (if clear), preconditions, attacker effort, and impact on confidentiality, integrity, and availability. Reflect signals like CVSS/EPSS, CISA KEV status, public exploit presence (GitHub, Metasploit, Exploit‑DB, Nuclei) where available. If data is unclear, write “Unknown”.

2. Potential Attack Scenarios
Describe at least one plausible end-to-end scenario: entry point, pre-auth vs post-auth, privilege required, lateral movement, and realistic outcomes (e.g., data theft, RCE, business downtime). If multiple paths exist, choose the highest-risk one and justify briefly.

3. Mitigation Recommendations
Provide concrete, prioritized actions. Include: patch/update guidance if a vendor fix is referenced, interim mitigations (network controls, feature disablement, WAF rules, config hardening), and detection/monitoring ideas. Only cite links that are present in the provided references; do NOT invent URLs. If patch availability is unclear, say “Patch status: Unknown”.

4. Executive Summary
Give a concise, two-paragraph summary for non-technical stakeholders: business risk, exploitation likelihood, and urgency. End with a clear call to action.

Strict formatting rules:
- Plain text only. No bullet points, no dashes, no markdown, no emojis.
- Each of the four headings must appear verbatim on its own line as above.
- Separate paragraphs with a single blank line.
- Do not add extra sections or a conclusion beyond the four sections.
- If you are unsure, write “Unknown” rather than speculating.

CVE DETAILS:
{cve_details}

FULL CVE DATA (for reference; use cautiously, do not copy raw JSON):
{json.dumps(cve_data, indent=2)}
"""
    return prompt


def get_risk_assessment(
    ai_provider: Optional[str],
    cve_details: str,
    cve_data: Dict[str, Any],
    *,
    config: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Route the prompt to the selected AI provider. If no provider is selected, return an explanatory message.
    """
    if not ai_provider:
        return "❌ No AI provider selected."

    cfg = config or load_config()
    prompt = generate_ai_prompt(cve_details, cve_data)

    # Normalize common aliases
    normalized = {
        "openai": "openai",
        "chatgpt": "openai",
        "gpt": "openai",
        "google": "google",
        "gemini": "google",
        "grok": "grok",
        "xai": "grok",
        "deepseek": "deepseek",
    }
    provider = normalized.get(ai_provider.lower(), ai_provider.lower())

    if provider == "openai":
        return get_openai_risk_assessment(prompt, cfg.get("openai_api_key"))

    if provider == "google":
        try:
            from .ai_providers.google_provider import get_google_risk_assessment
        except Exception as e:
            return f"❌ Google provider not available: {e}"
        return get_google_risk_assessment(prompt, cfg.get("google_ai_api_key"))

    if provider == "grok":
        try:
            from .ai_providers.grok_provider import get_grok_risk_assessment
        except Exception as e:
            return f"❌ Grok provider not available: {e}"
        return get_grok_risk_assessment(prompt, cfg.get("grok_api_key"))

    if provider == "deepseek":
        try:
            from .ai_providers.deepseek_provider import get_deepseek_risk_assessment
        except Exception as e:
            return f"❌ DeepSeek provider not available: {e}"
        return get_deepseek_risk_assessment(prompt, cfg.get("deepseek_api_key"))

    return "❌ Unknown AI provider selected."
