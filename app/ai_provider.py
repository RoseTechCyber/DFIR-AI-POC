"""Configurable AI provider for local development and Render."""

import os


def generate_analysis(prompt: str) -> str:
    """Generate an advisory analysis using the configured provider."""

    provider = os.getenv("AI_PROVIDER", "ollama").strip().lower()

    if provider == "gemini":
        from google import genai
        from google.genai import types

        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise RuntimeError(
                "GEMINI_API_KEY is required when AI_PROVIDER=gemini."
            )

        model = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")
        client = genai.Client(api_key=api_key)

        response = client.models.generate_content(
            model=model,
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.1,
                max_output_tokens=1200,
            ),
        )

        if not response.text:
            raise RuntimeError("Gemini returned no text.")

        return response.text

    if provider == "ollama":
        import ollama

        host = os.getenv(
            "OLLAMA_HOST",
            "http://127.0.0.1:11434",
        )
        model = os.getenv("OLLAMA_MODEL", "qwen2.5:0.5b")

        client = ollama.Client(host=host)
        response = client.generate(
            model=model,
            prompt=prompt,
        )

        return response.get("response", "No response from Ollama.")

    if provider == "disabled":
        return (
            "AI analysis is disabled. "
            "Review the deterministic assessment below."
        )

    raise RuntimeError(
        "Unsupported AI_PROVIDER. Use gemini, ollama, or disabled."
    )
