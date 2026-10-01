"""LLM provider abstraction.

``AIProvider`` is the single interface the rest of the system depends on.
Implementations:

* :class:`OpenAICompatibleProvider` - any server exposing ``/v1/chat/completions``
  (OpenAI, Azure-compatible gateways, vLLM, LM Studio, llama.cpp server,
  OpenRouter, Groq, ...).
* :class:`OllamaProvider` - a local Ollama server (``/api/chat``).

When no provider is configured the system uses the deterministic explanation
engine (``deterministic.py``), so it works fully offline.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

import httpx

from app.core.exceptions import AIProviderError


@dataclass
class ChatMessageIn:
    role: str  # system | user | assistant
    content: str


@dataclass
class ProviderConfig:
    provider: str
    base_url: str
    model: str
    api_key: str = ""
    timeout: int = 60
    temperature: float = 0.1


class AIProvider(ABC):
    name: str = "abstract"

    def __init__(self, config: ProviderConfig):
        self.config = config

    @abstractmethod
    def complete(self, messages: list[ChatMessageIn], *, json_mode: bool = False) -> str:
        ...

    def health(self) -> dict:
        try:
            out = self.complete([ChatMessageIn("user", "Reply with the single word OK.")])
            return {"ok": True, "detail": out[:50]}
        except AIProviderError as exc:
            return {"ok": False, "detail": exc.message}


class OpenAICompatibleProvider(AIProvider):
    name = "openai"

    def complete(self, messages: list[ChatMessageIn], *, json_mode: bool = False) -> str:
        if not self.config.base_url or not self.config.model:
            raise AIProviderError("OpenAI-compatible provider requires AI_BASE_URL and AI_MODEL.")
        url = self.config.base_url.rstrip("/") + "/chat/completions"
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        body: dict = {"model": self.config.model, "temperature": self.config.temperature,
                      "messages": [{"role": m.role, "content": m.content} for m in messages]}
        if json_mode:
            body["response_format"] = {"type": "json_object"}
        try:
            resp = httpx.post(url, json=body, headers=headers, timeout=self.config.timeout)
            if resp.status_code == 400 and json_mode:  # some servers lack response_format support
                body.pop("response_format", None)
                resp = httpx.post(url, json=body, headers=headers, timeout=self.config.timeout)
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"] or ""
        except httpx.HTTPStatusError as exc:
            raise AIProviderError(f"LLM API returned HTTP {exc.response.status_code}.") from exc
        except (httpx.HTTPError, KeyError, IndexError, ValueError) as exc:
            raise AIProviderError(f"LLM API request failed: {type(exc).__name__}") from exc


class OllamaProvider(AIProvider):
    name = "ollama"

    def complete(self, messages: list[ChatMessageIn], *, json_mode: bool = False) -> str:
        base = (self.config.base_url or "http://localhost:11434").rstrip("/")
        if not self.config.model:
            raise AIProviderError("Ollama provider requires AI_MODEL (e.g. llama3.1:8b).")
        body: dict = {"model": self.config.model, "stream": False,
                      "options": {"temperature": self.config.temperature},
                      "messages": [{"role": m.role, "content": m.content} for m in messages]}
        if json_mode:
            body["format"] = "json"
        try:
            resp = httpx.post(base + "/api/chat", json=body, timeout=self.config.timeout)
            resp.raise_for_status()
            return resp.json()["message"]["content"] or ""
        except httpx.HTTPStatusError as exc:
            raise AIProviderError(f"Ollama returned HTTP {exc.response.status_code}.") from exc
        except (httpx.HTTPError, KeyError, ValueError) as exc:
            raise AIProviderError(f"Ollama request failed: {type(exc).__name__}") from exc


PROVIDERS: dict[str, type[AIProvider]] = {"openai": OpenAICompatibleProvider, "ollama": OllamaProvider}


def build_provider(config: ProviderConfig) -> AIProvider | None:
    cls = PROVIDERS.get(config.provider)
    return cls(config) if cls else None
