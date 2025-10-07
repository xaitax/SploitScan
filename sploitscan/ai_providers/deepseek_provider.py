"""
DeepSeek provider for AI-powered risk assessment.
"""

from __future__ import annotations

from typing import Optional
import time

from openai import OpenAI  # type: ignore[import-untyped]


def get_deepseek_risk_assessment(prompt: str, api_key: Optional[str]) -> str:
    """
    DeepSeek via OpenAI-compatible API.
    - Endpoint: https://api.deepseek.com
    - Model: deepseek-chat
    - Deterministic output: temperature=0, stream=False
    - Retries: simple backoff to tolerate transient timeouts
    """
    if not api_key:
        return "❌ DeepSeek API key is not configured correctly."
    try:
        client = OpenAI(api_key=api_key, base_url="https://api.deepseek.com")
    except Exception as e:
        return f"❌ Error initializing DeepSeek client: {e}"

    last_err: Optional[str] = None
    for attempt in range(3):
        try:
            response = client.chat.completions.create(
                model="deepseek-chat",
                messages=[
                    {"role": "system", "content": "You are a security analyst."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0,
                stream=False,
                timeout=60,
            )
            if response.choices and len(response.choices) > 0:
                message = response.choices[0].message
                content = getattr(message, "content", None)
                return (content or str(message) or "").strip()
            return "DeepSeek: No response received."
        except Exception as e:
            last_err = str(e)
            if attempt < 2:
                time.sleep(3 * (attempt + 1))
                continue
            return f"❌ Error fetching data from DeepSeek: {last_err or 'Unknown error'}"
    