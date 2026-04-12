#!/usr/bin/env python3
"""
Context Compactor — kompresja historii wiadomości.
Wzorowane na Claude Code auto-compaction.

Gemma 4 ma 128k context, ale dla szybkości używamy 8-32k.
Kiedy messages przekraczają limit, kompresujemy stare wiadomości
do podsumowania, zachowując system prompt + ostatnie N.
"""

import json
import requests
from typing import Optional

# Przyblizone tokeny na znak (dla modeli wielojezycznych)
CHARS_PER_TOKEN = 3.5


def estimate_tokens(messages: list) -> int:
    """Oszacuj liczbę tokenów w messages."""
    total_chars = 0
    for msg in messages:
        content = msg.get("content", "")
        if isinstance(content, str):
            total_chars += len(content)
        # tool_calls
        tc = msg.get("tool_calls", [])
        if tc:
            total_chars += len(json.dumps(tc))
    return int(total_chars / CHARS_PER_TOKEN)


def should_compact(messages: list, max_tokens: int = 6000) -> bool:
    """Czy trzeba kompresować? Zostaw margines dla odpowiedzi."""
    return estimate_tokens(messages) > max_tokens


def compact_messages(
    messages: list,
    ollama_url: str,
    model: str,
    keep_last: int = 6,
    max_tokens: int = 6000
) -> list:
    """
    Skompresuj starsze wiadomości do podsumowania.

    Zachowuje:
    - messages[0] = system prompt (zawsze)
    - ostatnie `keep_last` wiadomości (najswiezszy kontekst)

    Kompresuje:
    - wszystko pomiędzy → jedno podsumowanie
    """
    if not should_compact(messages, max_tokens):
        return messages

    if len(messages) <= keep_last + 2:
        return messages

    system_msg = messages[0] if messages[0].get("role") == "system" else None
    start_idx = 1 if system_msg else 0

    # wiadomości do kompresji vs do zachowania
    to_compress = messages[start_idx:-keep_last]
    to_keep = messages[-keep_last:]

    if not to_compress:
        return messages

    # zbuduj podsumowanie z kompresowanych wiadomości
    summary = _summarize(to_compress, ollama_url, model)

    # złóż nową listę
    result = []
    if system_msg:
        result.append(system_msg)

    result.append({
        "role": "assistant",
        "content": f"[Podsumowanie wcześniejszej rozmowy]\n{summary}"
    })
    result.extend(to_keep)

    return result


def _summarize(messages: list, ollama_url: str, model: str) -> str:
    """Wygeneruj podsumowanie wiadomości przez model."""
    # zbuduj tekst do podsumowania
    parts = []
    for msg in messages:
        role = msg.get("role", "?")
        content = msg.get("content", "")

        if role == "tool":
            tool_name = msg.get("name", "?")
            # skróć wyniki narzędzi
            if len(content) > 200:
                content = content[:200] + "..."
            parts.append(f"[tool:{tool_name}] {content}")
        elif role == "assistant":
            tc = msg.get("tool_calls", [])
            if tc:
                tools_used = [t.get("function", {}).get("name", "?") for t in tc]
                parts.append(f"Agent użył: {', '.join(tools_used)}")
            if content:
                parts.append(f"Agent: {content[:300]}")
        elif role == "user":
            parts.append(f"User: {content[:200]}")

    conversation_text = "\n".join(parts)

    # jeśli tekst jest krótki, zwróć go bez LLM
    if len(conversation_text) < 500:
        return conversation_text

    # użyj modelu do podsumowania
    try:
        resp = requests.post(
            f"{ollama_url}/api/chat",
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": "Streść poniższą rozmowę w 3-5 zdaniach. Zachowaj kluczowe fakty, decyzje i wyniki narzędzi. Odpowiedz TYLKO streszczeniem."},
                    {"role": "user", "content": conversation_text[:3000]}
                ],
                "stream": False,
                "options": {"temperature": 0.3, "num_ctx": 4096}
            },
            timeout=30
        )
        resp.raise_for_status()
        return resp.json().get("message", {}).get("content", conversation_text[:500])
    except Exception:
        # fallback: mechaniczne skrócenie
        return _mechanical_summary(messages)


def _mechanical_summary(messages: list) -> str:
    """Fallback: podsumowanie bez LLM."""
    user_msgs = [m["content"][:100] for m in messages if m.get("role") == "user"]
    tools_used = []
    for m in messages:
        if m.get("role") == "assistant" and m.get("tool_calls"):
            for tc in m["tool_calls"]:
                tools_used.append(tc.get("function", {}).get("name", "?"))

    parts = []
    if user_msgs:
        parts.append(f"Tematy: {'; '.join(user_msgs[:5])}")
    if tools_used:
        unique_tools = list(dict.fromkeys(tools_used))
        parts.append(f"Użyte narzędzia: {', '.join(unique_tools)}")
    parts.append(f"Wymiana: {len(messages)} wiadomości")

    return "\n".join(parts)
