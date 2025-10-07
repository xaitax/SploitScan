"""
OpenAI provider for AI-powered risk assessment.
"""

from __future__ import annotations

from typing import Optional
import time

from openai import OpenAI  # type: ignore[import-untyped]


def get_openai_risk_assessment(prompt: str, api_key: Optional[str]) -> str:
    """
    OpenAI Chat Completions with deterministic settings and simple retries.
    - Model: gpt-4o (can be adjusted later)
    - temperature=0, stream=False
    - timeout=60
    - retries with incremental backoff
    """
    if not api_key:
        return "❌ OpenAI API key is not configured correctly."

    try:
        client = OpenAI(api_key=api_key)
    except Exception as e:
        return f"❌ Error initializing OpenAI client: {e}"

    last_err: Optional[str] = None
    for attempt in range(3):
        try:
            response = client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": "You are a security analyst."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0,
                stream=False,
                timeout=60,
            )
            content = response.choices[0].message.content if response.choices else None
            return (content or "").strip()
        except Exception as e:
            last_err = str(e)
            if attempt < 2:
                time.sleep(3 * (attempt + 1))
                continue
            return f"❌ Error fetching data from OpenAI: {last_err or 'Unknown error'}"
