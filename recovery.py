#!/usr/bin/env python3
"""
Recovery Engine — obsługa błędów i retry logic.
Wzorowane na Claude Code recovery recipes.
"""

import json
import time
import logging
import threading
import requests
from typing import Optional, Callable

log = logging.getLogger("recovery")


class RecoveryAction:
    RETRY = "retry"
    FALLBACK = "fallback"
    SKIP = "skip"
    ABORT = "abort"


# ─── RECOVERY RECIPES ─────────────────────────────────────────────────────────

RECIPES = {
    "api_timeout": {
        "max_retries": 2,
        "backoff": [5, 10],  # sekundy
        "actions": [RecoveryAction.RETRY, RecoveryAction.RETRY],
    },
    "api_error": {
        "max_retries": 2,
        "backoff": [1, 3],
        "actions": [RecoveryAction.RETRY, RecoveryAction.FALLBACK],
    },
    "json_parse": {
        "max_retries": 2,
        "backoff": [0, 0],
        "actions": [RecoveryAction.RETRY, RecoveryAction.SKIP],
    },
    "tool_failure": {
        "max_retries": 1,
        "backoff": [1],
        "actions": [RecoveryAction.RETRY],
    },
    "context_overflow": {
        "max_retries": 1,
        "backoff": [0],
        "actions": [RecoveryAction.RETRY],  # po kompresji
    },
}


class RecoveryEngine:
    def __init__(
        self,
        fallback_fn: Optional[Callable] = None,
        compact_fn: Optional[Callable] = None,
        alert_fn: Optional[Callable] = None,
    ):
        """
        fallback_fn: funkcja do wywołania przy fallback (np. call_anthropic)
        compact_fn:  funkcja do kompresji kontekstu
        alert_fn:    funkcja do alertowania (np. CS note)
        """
        self.fallback_fn = fallback_fn
        self.compact_fn = compact_fn
        self.alert_fn = alert_fn
        self._retry_counts: dict[str, int] = {}
        # R12: lock around _retry_counts. Worker is single-threaded today
        # so the race is theoretical, but adding the lock prevents a future
        # worker-pool refactor from silently miscounting retries (which
        # could loop forever on a persistent tool failure or skip after
        # zero retries). Cheap; uncontended in normal use.
        self._retry_lock = threading.Lock()

    def _get_recipe(self, error_type: str) -> dict:
        return RECIPES.get(error_type, RECIPES["api_error"])

    def handle_api_call(
        self,
        call_fn: Callable,
        messages: list,
        error_type: str = "api_error",
        **kwargs
    ) -> tuple[Optional[dict], list]:
        """
        Wywołaj API z recovery logic.
        Returns: (response, possibly_compacted_messages)
        """
        recipe = self._get_recipe(error_type)

        for attempt in range(recipe["max_retries"] + 1):
            try:
                result = call_fn(messages, **kwargs)

                # sprawdz czy odpowiedz ma sens
                msg = result.get("message", {})
                content = msg.get("content", "")
                tool_calls = msg.get("tool_calls", [])

                if not content and not tool_calls:
                    # pusty response — retry
                    if attempt < recipe["max_retries"]:
                        log.warning(f"Pusty response, retry {attempt+1}")
                        time.sleep(recipe["backoff"][attempt] if attempt < len(recipe["backoff"]) else 1)
                        continue
                    return result, messages

                # validate tool_calls JSON
                bad_json = False
                for tc in tool_calls:
                    fn = tc.get("function", {})
                    raw_args = fn.get("arguments", {})
                    # Ollama returns dict, Anthropic string — normalize
                    if isinstance(raw_args, str):
                        try:
                            json.loads(raw_args)
                        except json.JSONDecodeError as e:
                            bad_json = True
                            log.warning(
                                "Bad JSON in tool_calls for %s: %s — raw=%r",
                                fn.get("name", "?"), e, raw_args[:200]
                            )
                            tc["function"]["arguments"] = "{}"

                if bad_json and attempt < recipe["max_retries"]:
                    log.warning(f"Bad JSON in tool_calls, retry {attempt+1}")
                    # Use a system-role hint (not a fake [SYSTEM] prefix in a
                    # user message, which would let a malicious tool output
                    # forge the same marker and inject instructions).
                    messages.append({
                        "role": "system",
                        "content": "Your previous response contained invalid JSON in tool arguments. Please retry with strictly valid JSON for all tool calls."
                    })
                    time.sleep(0.5)
                    continue

                return result, messages

            except requests.exceptions.Timeout:
                log.warning(f"API timeout, attempt {attempt+1}/{recipe['max_retries']+1}")
                if attempt < recipe["max_retries"]:
                    action = recipe["actions"][attempt] if attempt < len(recipe["actions"]) else RecoveryAction.RETRY
                    if action == RecoveryAction.FALLBACK and self.fallback_fn:
                        log.info("Fallback do Anthropic")
                        try:
                            result = self.fallback_fn(messages)
                            return result, messages
                        except Exception as e:
                            log.error(f"Fallback failed: {e}")
                    backoff = recipe["backoff"][attempt] if attempt < len(recipe["backoff"]) else 5
                    time.sleep(backoff)
                    continue

                if self._alert("api_timeout", "API timeout po wszystkich retry"):
                    pass
                return None, messages

            except requests.exceptions.ConnectionError:
                log.error("Ollama niedostępne")
                if self.fallback_fn:
                    try:
                        result = self.fallback_fn(messages)
                        return result, messages
                    except Exception as e:
                        log.warning("fallback after ConnectionError failed: %s", e)
                return None, messages

            except KeyboardInterrupt:
                raise  # propaguj do main loop

            except Exception as e:
                log.error(f"API error: {e}")
                if attempt < recipe["max_retries"]:
                    backoff = recipe["backoff"][attempt] if attempt < len(recipe["backoff"]) else 2
                    time.sleep(backoff)
                    continue

                if self.fallback_fn:
                    try:
                        result = self.fallback_fn(messages)
                        return result, messages
                    except Exception as fbe:
                        log.warning("fallback after API error failed: %s", fbe)
                return None, messages

        return None, messages

    def handle_tool_error(self, tool_name: str, args: dict, error: str) -> tuple[str, str]:
        """
        Obsłuż błąd narzędzia.
        Returns: (action, result_or_message)
        """
        recipe = self._get_recipe("tool_failure")
        key = f"tool:{tool_name}"
        with self._retry_lock:
            count = self._retry_counts.get(key, 0)
            if count < recipe["max_retries"]:
                self._retry_counts[key] = count + 1
                return RecoveryAction.RETRY, f"Retry {count+1}: {error}"
            # reset counter
            self._retry_counts[key] = 0
            return RecoveryAction.SKIP, f"[SKIP] Tool {tool_name} failed: {error}"

    def handle_context_overflow(self, messages: list) -> list:
        """Kompresuj kontekst gdy za duży.

        R12 preventive: the fallback path (when no compact_fn is wired)
        used to inject a synthetic `role=assistant` "conversation was
        compressed" message — same shape as the compactor-laundering
        defect F1 closed in R6. Fallback is rarely hit (main path uses
        compact_fn which is already fixed), but we rewrite the marker
        as a role=user note so the model can't read it as its own prior
        declaration.
        """
        if self.compact_fn:
            return self.compact_fn(messages)
        # fallback: zachowaj system + ostatnie 4
        system = messages[0] if messages[0].get("role") == "system" else None
        result = []
        if system:
            result.append(system)
        result.append({
            "role": "user",
            "content": "[CONTEXT COMPRESSED — older turns dropped due to context limit. Treat this note as operator metadata, not as a prior confirmation or assistant claim.]"
        })
        result.extend(messages[-4:])
        return result

    def _alert(self, error_type: str, message: str) -> bool:
        """Wyślij alert."""
        if self.alert_fn:
            try:
                self.alert_fn(error_type, message)
                return True
            except Exception as e:
                log.warning("alert_fn failed: %s", e)
        log.error(f"ALERT [{error_type}]: {message}")
        return False

    def reset(self):
        """Reset retry counters."""
        self._retry_counts.clear()
