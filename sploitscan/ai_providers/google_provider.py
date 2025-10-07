"""
Google Gemini provider for AI-powered risk assessment.
"""

from __future__ import annotations

import time
from typing import Optional

from google import genai  # type: ignore[import-untyped]


def get_google_risk_assessment(prompt: str, api_key: Optional[str]) -> str:
    if not api_key:
        return "❌ Google AI API key is not configured correctly."

    client = genai.Client(api_key=api_key)
    # retry a couple of times similar to legacy behavior
    for attempt in range(3):
        try:
            response = client.models.generate_content(
                model="gemini-2.0-flash",
                contents=[prompt],
                generation_config={
                    "temperature": 0,
                    "top_p": 0.9
                },
            )
            if hasattr(response, "text"):
                return (response.text or "").strip()
            return "Google AI: AI analysis failed."
        except Exception as e:
            if attempt < 2:
                print(f"⚠️ Google AI Timeout (Attempt {attempt + 1}/3), retrying...")
                time.sleep(5)
            else:
                return f"❌ Error fetching data from Google AI: {e}"
