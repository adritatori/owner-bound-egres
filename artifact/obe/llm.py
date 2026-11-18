"""Tiny Ollama client. Ollama runs the model locally (on your RTX 3050).

Every call is recorded in `self.trace` (prompt, reply, settings, timing,
token counts) so experiments can be re-analysed later without re-running.
"""
import time

import requests


class OllamaClient:
    def __init__(self, model="qwen2.5:3b", base_url="http://localhost:11434", timeout=120,
                 temperature=0.0):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.temperature = float(temperature)
        self.calls = 0
        self.max_retries = 6
        self.trace = []   # one dict per call; caller drains it with pop_trace()

    def chat(self, prompt, seed=0, purpose=""):
        self.calls += 1
        t0 = time.perf_counter()
        # Retry ONLY on server failures (HTTP 5xx, timeout, dropped connection).
        # The request body is identical on every attempt (same prompt, seed,
        # temperature), so a successful reply is the same as a first-try reply.
        # Calls that succeed first time behave exactly as before.
        retries = 0
        while True:
            try:
                r = requests.post(
                    f"{self.base_url}/api/chat",
                    json={
                        "model": self.model,
                        "messages": [{"role": "user", "content": prompt}],
                        "stream": False,
                        "options": {"temperature": self.temperature, "seed": seed},
                    },
                    timeout=max(self.timeout, 300),
                )
                if r.status_code >= 500:
                    raise requests.HTTPError(f"{r.status_code} from Ollama: {r.text[:300]}", response=r)
                r.raise_for_status()
                break
            except (requests.Timeout, requests.ConnectionError, requests.HTTPError) as e:
                resp = getattr(e, "response", None)
                if resp is not None and resp.status_code < 500:
                    raise                      # 4xx = real bug, do not hide it
                retries += 1
                if retries > self.max_retries:
                    raise
                wait = min(10 * retries, 60)
                print(f"[llm:{self.model}] attempt {retries} failed ({type(e).__name__}: {str(e)[:200]}); "
                      f"retrying in {wait}s", flush=True)
                time.sleep(wait)
        data = r.json()
        reply = data["message"]["content"]
        self.trace.append({
            "model": self.model, "temperature": self.temperature, "seed": seed, "purpose": purpose,
            "prompt": prompt, "reply": reply, "latency_s": round(time.perf_counter() - t0, 4),
            "prompt_tokens": data.get("prompt_eval_count"), "reply_tokens": data.get("eval_count"),
        })
        if retries:
            self.trace[-1]["retries"] = retries   # only present when a retry happened
        return reply

    def pop_trace(self):
        out, self.trace = self.trace, []
        return out


class FakeClient:
    """Offline stand-in with the same interface, for tests (no model needed).

    `responder(prompt, seed)` returns the reply text.
    """

    def __init__(self, responder, model="fake"):
        self.responder = responder
        self.model = model
        self.temperature = 0.0
        self.calls = 0
        self.trace = []

    def chat(self, prompt, seed=0, purpose=""):
        self.calls += 1
        reply = self.responder(prompt, seed)
        self.trace.append({"model": self.model, "temperature": 0.0, "seed": seed, "purpose": purpose,
                           "prompt": prompt, "reply": reply, "latency_s": 0.0,
                           "prompt_tokens": None, "reply_tokens": None})
        return reply

    def pop_trace(self):
        out, self.trace = self.trace, []
        return out
