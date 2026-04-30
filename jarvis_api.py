"""
J.A.R.V.I.S. STANDALONE CLI TESTER
=====================================
Standalone script to test the JARVIS brain directly from the terminal.
Uses OpenAI GPT-4o (PentestGPT mode).

Usage:
    1. Set OPENAI_API_KEY in your .env file
    2. Run: python jarvis_api.py
"""

import json
import os
import sys
from dotenv import load_dotenv

load_dotenv()

print("===================================================")
print(" 🧠 J.A.R.V.I.S. LIVE API ADVISORY ENGINE ONLINE")
print("     Powered by OpenAI GPT-4o (PentestGPT Mode)")
print("===================================================")

API_KEY = os.getenv("OPENAI_API_KEY", "")

if not API_KEY:
    print("\n[ERROR] OPENAI_API_KEY is not set.")
    print("  1. Get a key from: https://platform.openai.com/api-keys")
    print("  2. Add it to your .env file: OPENAI_API_KEY=sk-...")
    sys.exit(1)

try:
    import openai
except ImportError:
    print("\n[ERROR] openai package not installed.")
    print("  Run: pip install openai")
    sys.exit(1)

JARVIS_SYSTEM = """You are J.A.R.V.I.S., an elite autonomous SOC analyst and PentestGPT-powered cybersecurity assistant.
Your role: Act as a tactical mentor for security analysts working on threat intelligence, CTFs, forensics, and penetration testing.

Be concise, tactical, and specific. Give actionable commands and always explain what they do.
Format with clear section headers and use plain text (this is a terminal, not HTML).
Use [ADVISORY], [WARNING], [COMMAND] style prefixes."""


def get_jarvis_advisory(user_prompt: str) -> str:
    """Send user prompt to OpenAI GPT-4o and return the response."""
    try:
        client = openai.OpenAI(api_key=API_KEY)
        completion = client.chat.completions.create(
            model="gpt-4o",
            max_tokens=1024,
            messages=[
                {"role": "system", "content": JARVIS_SYSTEM},
                {"role": "user",   "content": user_prompt}
            ]
        )
        return completion.choices[0].message.content

    except openai.AuthenticationError:
        return "[-] CRITICAL ERROR: Invalid API key. Check OPENAI_API_KEY in your .env file."
    except openai.RateLimitError:
        return "[-] RATE LIMIT: OpenAI quota reached. Try again shortly or upgrade your plan."
    except openai.APIConnectionError:
        return "[-] CONNECTION ERROR: Could not reach OpenAI API. Check your internet connection."
    except Exception as e:
        return f"[-] UNEXPECTED ERROR: {str(e)}"


print(f"\n [*] API Key loaded: sk-...{API_KEY[-6:]}")
print(" [*] Model: gpt-4o (PentestGPT mode active)")
print(" [*] Type a hacking scenario you are stuck on.")
print(" [*] Type 'exit' to quit.")
print("=" * 50)

while True:
    try:
        user_input = input("\n[Operator]> ")
    except (KeyboardInterrupt, EOFError):
        print("\nShutting down JARVIS API connection...")
        break

    if user_input.lower() in ("exit", "quit", "q"):
        print("Shutting down JARVIS API connection...")
        break

    if not user_input.strip():
        continue

    print("\n[*] Transmitting to OpenAI GPT-4o...")

    response = get_jarvis_advisory(user_input)
    print(f"\n[J.A.R.V.I.S.]\n{'-' * 40}\n{response}\n{'-' * 40}")