"""Start the Ward console: a chat with the master agent plus live identity/security views.

  uv run python -m scripts.ward                 # http://127.0.0.1:8000/
  uv run python -m scripts.ward --port 8001

The master agent is an LLM. By default it's a small local model through Ollama
(`ollama pull qwen2.5:3b`). Set BADGE_LLM_PROVIDER=openai, BADGE_LLM_BASE_URL and
BADGE_LLM_API_KEY to use Groq or another OpenAI-compatible API instead.
"""

from __future__ import annotations

import argparse
import os

import uvicorn

from ward.env import load_dotenv

load_dotenv()  # before the app reads GROQ_API_KEY / BADGE_* settings

from server.ward_app import create_app


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", 8000)))
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()
    app = create_app(persist=True)
    llm = app.state.console.model
    # DEMO_HARDCODE: print the shared demo operator passwords for local hackathon use.
    print(f"\n  Badge · Ward console  →  http://{args.host}:{args.port}/")
    print(
        "  Operator logins: alice / ward-demo-Qx7m, bob / ward-demo-Kp3v"
        " (override with WARD_OPERATORS)"
    )
    from agents.runner import llm_settings

    print(f"  Master agent model: {llm} via {llm_settings()[0]}\n")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
