"""Plain-English explanation of a detector alert, for non-experts watching the dashboard.

  explain(note, result)   -> instant template sentence (always available)
  AI.get(event)           -> GenAI summary from a local LLM, or None while it is still being written

The GenAI summary is written by a local model through Ollama (no API key, nothing leaves the
machine). It runs in a background thread and is cached per kind of alert, so the dashboard never
waits on it. The model only rephrases the facts below; the technical reason stays visible.

  OLLAMA_URL    default http://localhost:11434
  OLLAMA_MODEL  default qwen2.5:7b   (llama3.2:3b is faster but mixes up "blocked" more often)
  EXPLAIN_AI=0  turn GenAI off
"""
import json
import os
import queue
import threading
import time
import urllib.request

# What each alert factor means for the data, in plain words.
PLAIN = {
    "pqc_stripped": "someone removed the quantum-safe options from this client's connection request, "
                    "forcing it onto old encryption that a future quantum computer could break",
    "pqc_offered_not_chosen": "the client asked for quantum-safe encryption but the connection ended up "
                              "on old encryption, which suggests someone tampered with the handshake",
    "chosen_pqc": "this connection uses old encryption that a future quantum computer could break",
    "offers_pqc": "this client did not ask for quantum-safe encryption at all",
    "strength_drop": "this client's encryption is weaker than it normally uses, a quiet way to downgrade security",
    "cipher_strength": "the connection uses weaker encryption settings than normal traffic",
    "tls13": "the client is using an older version of the security protocol than normal traffic",
    "conn_per_min": "this client is connecting far more often than normal, like a script trying to grab data",
    "conn_per_10min": "this client has made an unusually large number of connections in the last few minutes",
    "new_group_set": "this client suddenly asked for a different set of encryption options than it ever has",
    "hour": "this activity is happening at an unusual time of day",
}


def explain(note, result):
    if result.get("by") == "watch":
        return (f"{note.get('client_id', 'A client')} connected once without quantum-safe encryption. "
                "Real devices occasionally do this harmlessly, so it is being watched; "
                "a repeat within 10 minutes raises an alarm.")
    if not result.get("alert"):
        return "Normal, quantum-safe traffic." if note.get("strong_or_weak") == "strong" \
            else "Normal traffic from a client that only supports older encryption."
    return template_explain(note, result)


def template_explain(note, result):
    parts = [PLAIN[f] for f in result.get("factors", []) if f in PLAIN]
    who = note.get("client_id", "a client")
    if not parts:
        text = f"The AI model found {who}'s connection unlike any normal traffic it has learned."
    else:
        text = f"{who}: {parts[0][0].upper()}{parts[0][1:]}."
        if len(parts) > 1:
            text += " Also, " + "; ".join(parts[1:]) + "."
    if result.get("by") == "model":
        text += " (Spotted by the AI model, not a fixed rule.)"
    if result.get("blocked"):
        text += " The gateway refused the connection, so no data was exposed."
    if result.get("prior_downgrades"):
        text += " This client was already caught in a downgrade earlier."
    return text


class LLMExplainer:
    """Background GenAI summaries, one per kind of alert (rule/model/watch + factors + blocked)."""

    def __init__(self):
        self.url = os.environ.get("OLLAMA_URL", "http://localhost:11434").rstrip("/")
        self.model = os.environ.get("OLLAMA_MODEL", "qwen2.5:7b")
        self.enabled = os.environ.get("EXPLAIN_AI", "1") != "0"
        self.cache, self.pending = {}, set()
        self.jobs = queue.Queue()
        self.status = "starting"
        self._next_probe = 0.0
        self._lock = threading.Lock()
        self._thread = None

    @staticmethod
    def key(ev):
        return (ev.get("by"), tuple(ev.get("factors") or ()), bool(ev.get("blocked")),
                bool(ev.get("prior_downgrades")))

    def get(self, ev):
        """Cached summary for this kind of alert, or None (and queue it) if not written yet."""
        if not self.enabled or not ev.get("by"):
            return None
        k = self.key(ev)
        with self._lock:
            if k in self.cache:
                return self.cache[k]
            if k not in self.pending and self._available():
                self.pending.add(k)
                self.jobs.put((k, dict(ev)))
                if self._thread is None:
                    self._thread = threading.Thread(target=self._work, daemon=True)
                    self._thread.start()
        return None

    def _available(self):
        """Is the model server up? Re-probed at most every 30 s when it is not."""
        if self.status == "ready":
            return True
        if time.time() < self._next_probe:
            return False
        self._next_probe = time.time() + 30
        try:
            with urllib.request.urlopen(self.url + "/api/tags", timeout=2) as r:
                names = [m["name"] for m in json.load(r).get("models", [])]
            self.status = "ready" if self.model in names else f"model {self.model} not pulled"
        except Exception:
            self.status = "no local LLM running"
        return self.status == "ready"

    def _work(self):
        while True:
            k, ev = self.jobs.get()
            try:
                text = self._ask(prompt(ev))
            except Exception as e:  # leave it uncached so a later poll retries
                self.status = f"error: {e}"
                with self._lock:
                    self.pending.discard(k)
                continue
            with self._lock:
                self.cache[k] = text
                self.pending.discard(k)

    def _ask(self, text):
        body = json.dumps({"model": self.model, "prompt": text, "stream": False,
                           "options": {"temperature": 0.2, "num_predict": 120}}).encode()
        req = urllib.request.Request(self.url + "/api/generate", body, {"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=180) as r:
            out = json.load(r)["response"]
        return " ".join(out.replace("*", "").split())[:420]


def prompt(ev):
    facts = [PLAIN[f] for f in ev.get("factors") or () if f in PLAIN]
    if ev.get("by") == "watch":
        facts.append("this happened once and everything else about the connection looks normal; "
                     "real devices occasionally do this harmlessly, so it is being watched, not alarmed")
    facts.append("the gateway refused the connection, so no data was exposed" if ev.get("blocked")
                 else "the connection was allowed through")
    if ev.get("prior_downgrades"):
        facts.append("this client was already caught in a downgrade earlier")
    facts.append("spotted by: " + {"rule": "a fixed security rule, confirmed by the AI model's view of the traffic",
                                   "model": "the AI model that learned what normal traffic looks like",
                                   "watch": "a fixed security rule"}[ev["by"]])
    return ("You explain alerts from a security gateway that protects a bank's old systems with "
            "quantum-safe encryption. Your reader is a non-technical bank manager.\n\n"
            "Facts (all true; do not add others):\n- " + "\n- ".join(facts) +
            "\n\nWrite exactly 2 short sentences: what happened, then what it means for the bank's data. "
            "Do not give advice or recommend settings. "
            "Do not claim data was stolen, read or intercepted unless a fact says so. "
            "Plain words, no technical terms, no names, no markdown, no preamble.")


AI = LLMExplainer()
