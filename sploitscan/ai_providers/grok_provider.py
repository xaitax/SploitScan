"""
xAI Grok provider for AI-powered risk assessment.
"""

from __future__ import annotations

from typing import Optional
import time

from openai import OpenAI  # type: ignore[import-untyped]


def get_grok_risk_assessment(prompt: str, api_key: Optional[str]) -> str:
    if not api_key:
        return "❌ Grok AI API key is not configured correctly."

    try:
        client = OpenAI(api_key=api_key, base_url="https://api.x.ai/v1")
    except Exception as e:
        return f"❌ Error initializing Grok client: {e}"

    last_err: Optional[str] = None
    for attempt in range(3):
        try:
            response = client.chat.completions.create(
                model="grok-4-latest",
                messages=[
                    {"role": "system", "content": "You are a security analyst."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0,
                stream=False,
                timeout=60,  # allow more time; xAI can be slower than OpenAI defaults
            )
            if response.choices and len(response.choices) > 0:
                message = response.choices[0].message
                content = getattr(message, "content", None)
                return (content or str(message) or "").strip()
            return "Grok AI: No response received."
        except Exception as e:
            last_err = str(e)
            if attempt < 2:
                time.sleep(3 * (attempt + 1))
                continue
            return f"❌ Error fetching data from Grok AI: {last_err or 'Unknown error'}"
