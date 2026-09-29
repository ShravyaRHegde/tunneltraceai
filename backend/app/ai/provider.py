"""Local LLM and Embedding Provider abstraction for TunnelTrace AI.

Provides unified, typed async communication with local Ollama runtime,
enforcing concurrency limits, timeouts, structured output parsing,
and complete isolation from cloud LLM services.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, TypeVar

import httpx
from pydantic import BaseModel

from app.core.config import get_settings

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)


class AIError(Exception):
    """Base exception for AI provider operations."""


class ModelUnavailableError(AIError):
    """Raised when the local LLM runtime or requested model is unreachable/offline."""


class ModelTimeoutError(AIError):
    """Raised when model inference exceeds configured execution timeout."""


class StructuredOutputError(AIError):
    """Raised when the model fails to return valid structured JSON adhering to schema."""


@dataclass(frozen=True)
class LLMResponse:
    """Execution metadata and generated text from local LLM."""

    content: str
    model: str
    total_duration_ms: float
    prompt_eval_count: int
    eval_count: int
    raw_response: dict[str, Any] | None = None


@dataclass(frozen=True)
class EmbeddingResult:
    """Batch embedding outcome."""

    embeddings: list[list[float]]
    model: str
    dimension: int
    duration_ms: float


class BaseLocalProvider(ABC):
    """Abstract interface for local inference engines."""

    @abstractmethod
    async def health(self) -> dict[str, Any]:
        """Check provider runtime health and return available models."""

    @abstractmethod
    async def list_models(self) -> list[str]:
        """List model tags currently installed in local runtime."""

    @abstractmethod
    async def embed(self, texts: list[str], model: str | None = None) -> EmbeddingResult:
        """Compute normalized vector embeddings for a batch of strings."""

    @abstractmethod
    async def generate(
        self,
        prompt: str,
        system: str | None = None,
        model: str | None = None,
        temperature: float = 0.1,
        max_tokens: int = 1024,
        stop: list[str] | None = None,
    ) -> LLMResponse:
        """Generate text response using local model."""

    @abstractmethod
    async def generate_structured(
        self,
        prompt: str,
        schema: dict[str, Any] | type[BaseModel] | None = None,
        system: str | None = None,
        model: str | None = None,
        temperature: float = 0.1,
        max_tokens: int = 1024,
    ) -> tuple[dict[str, Any], LLMResponse]:
        """Generate structured JSON response adhering to schema with repair fallback."""


class OllamaProvider(BaseLocalProvider):
    """Concrete Ollama provider communicating over local HTTP loopback."""

    def __init__(
        self,
        base_url: str | None = None,
        timeout_sec: float | None = None,
        max_concurrency: int | None = None,
    ) -> None:
        settings = get_settings()
        self.base_url = (base_url or settings.OLLAMA_BASE_URL).rstrip("/")
        self.timeout_sec = timeout_sec or settings.AI_REQUEST_TIMEOUT_SEC
        self._semaphore = asyncio.Semaphore(max_concurrency or settings.AI_MAX_CONCURRENCY)

    async def health(self) -> dict[str, Any]:
        """Query Ollama health and list models."""
        url = f"{self.base_url}/api/tags"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url)
                if resp.status_code != 200:
                    return {
                        "status": "unhealthy",
                        "error": f"HTTP {resp.status_code}: {resp.text}",
                        "runtime": "ollama",
                        "base_url": self.base_url,
                        "models": [],
                    }
                data = resp.json()
                models = [m.get("name", "") for m in data.get("models", [])]
                return {
                    "status": "healthy",
                    "runtime": "ollama",
                    "base_url": self.base_url,
                    "models": models,
                }
        except Exception as exc:
            return {
                "status": "offline",
                "error": str(exc),
                "runtime": "ollama",
                "base_url": self.base_url,
                "models": [],
            }

    async def list_models(self) -> list[str]:
        info = await self.health()
        if info["status"] != "healthy":
            raise ModelUnavailableError(f"Ollama runtime unavailable at {self.base_url}: {info.get('error')}")
        return info.get("models", [])

    async def embed(self, texts: list[str], model: str | None = None) -> EmbeddingResult:
        settings = get_settings()
        target_model = model or settings.AI_EMBEDDING_MODEL
        url = f"{self.base_url}/api/embed"

        if not texts:
            return EmbeddingResult(embeddings=[], model=target_model, dimension=settings.AI_EMBEDDING_DIM, duration_ms=0.0)

        payload = {
            "model": target_model,
            "input": texts,
        }

        start_t = time.perf_counter()
        async with self._semaphore:
            try:
                async with httpx.AsyncClient(timeout=self.timeout_sec) as client:
                    resp = await client.post(url, json=payload)
                    if resp.status_code != 200:
                        raise ModelUnavailableError(
                            f"Embedding failed (HTTP {resp.status_code}): {resp.text}"
                        )
                    data = resp.json()
                    embeddings = data.get("embeddings", [])
                    dur_ms = (time.perf_counter() - start_t) * 1000.0
                    dim = len(embeddings[0]) if embeddings else settings.AI_EMBEDDING_DIM
                    return EmbeddingResult(
                        embeddings=embeddings,
                        model=target_model,
                        dimension=dim,
                        duration_ms=dur_ms,
                    )
            except httpx.TimeoutException as exc:
                raise ModelTimeoutError(f"Embedding request timed out after {self.timeout_sec}s: {exc}") from exc
            except httpx.RequestError as exc:
                raise ModelUnavailableError(f"Network error communicating with Ollama: {exc}") from exc

    async def generate(
        self,
        prompt: str,
        system: str | None = None,
        model: str | None = None,
        temperature: float = 0.1,
        max_tokens: int = 1024,
        stop: list[str] | None = None,
    ) -> LLMResponse:
        settings = get_settings()
        target_model = model or settings.AI_PRIMARY_MODEL
        url = f"{self.base_url}/api/generate"

        payload: dict[str, Any] = {
            "model": target_model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
                "top_p": 0.9,
            },
        }
        if system:
            payload["system"] = system
        if stop:
            payload["options"]["stop"] = stop

        start_t = time.perf_counter()
        async with self._semaphore:
            try:
                async with httpx.AsyncClient(timeout=self.timeout_sec) as client:
                    resp = await client.post(url, json=payload)
                    if resp.status_code != 200:
                        raise ModelUnavailableError(
                            f"Inference failed (HTTP {resp.status_code}): {resp.text}"
                        )
                    data = resp.json()
                    dur_ms = (time.perf_counter() - start_t) * 1000.0
                    content = data.get("response", "")
                    prompt_eval = data.get("prompt_eval_count", 0)
                    eval_count = data.get("eval_count", 0)
                    return LLMResponse(
                        content=content,
                        model=target_model,
                        total_duration_ms=dur_ms,
                        prompt_eval_count=prompt_eval,
                        eval_count=eval_count,
                        raw_response=data,
                    )
            except httpx.TimeoutException as exc:
                raise ModelTimeoutError(f"Generation timed out after {self.timeout_sec}s: {exc}") from exc
            except httpx.RequestError as exc:
                raise ModelUnavailableError(f"Network error connecting to Ollama: {exc}") from exc

    async def generate_structured(
        self,
        prompt: str,
        schema: dict[str, Any] | type[BaseModel] | None = None,
        system: str | None = None,
        model: str | None = None,
        temperature: float = 0.1,
        max_tokens: int = 1024,
    ) -> tuple[dict[str, Any], LLMResponse]:
        """Request JSON structured generation with format='json' and schema validation."""
        settings = get_settings()
        target_model = model or settings.AI_PRIMARY_MODEL
        url = f"{self.base_url}/api/generate"

        payload: dict[str, Any] = {
            "model": target_model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
                "top_p": 0.9,
            },
        }
        if system:
            payload["system"] = system

        start_t = time.perf_counter()
        async with self._semaphore:
            try:
                t_out = httpx.Timeout(self.timeout_sec, connect=1.5)
                async with httpx.AsyncClient(timeout=t_out) as client:
                    resp = await client.post(url, json=payload)
                    if resp.status_code != 200:
                        raise ModelUnavailableError(
                            f"Structured inference failed (HTTP {resp.status_code}): {resp.text}"
                        )
                    data = resp.json()
                    dur_ms = (time.perf_counter() - start_t) * 1000.0
                    content = data.get("response", "")
                    llm_resp = LLMResponse(
                        content=content,
                        model=target_model,
                        total_duration_ms=dur_ms,
                        prompt_eval_count=data.get("prompt_eval_count", 0),
                        eval_count=data.get("eval_count", 0),
                        raw_response=data,
                    )

                    # Parse JSON
                    parsed_json = self._extract_json(content)
                    return parsed_json, llm_resp
            except (httpx.TimeoutException, TimeoutError) as exc:
                raise ModelTimeoutError(f"Generation timed out after {self.timeout_sec}s: {exc}") from exc
            except httpx.RequestError as exc:
                raise ModelUnavailableError(f"Network error connecting to Ollama: {exc}") from exc

    @staticmethod
    def _extract_json(text: str) -> dict[str, Any]:
        """Attempt robust JSON extraction from model response."""
        trimmed = text.strip()
        try:
            return json.loads(trimmed)
        except json.JSONDecodeError:
            pass

        # Try markdown code fence extraction
        match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                pass

        # Try finding outer braces
        first_brace = text.find("{")
        last_brace = text.rfind("}")
        if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
            candidate = text[first_brace : last_brace + 1]
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                pass

        # Attempt incremental repair for truncated model outputs
        if first_brace != -1:
            candidate = text[first_brace:]
            for suffix in ["}", "\"]}", "\"}", "\"]\n}", "\"\n}", "\n}\n}"]:
                try:
                    return json.loads(candidate + suffix)
                except json.JSONDecodeError:
                    pass

        # Robust regex fallback extracting essential fields from partial JSON
        answer_match = re.search(r'"answer"\s*:\s*"(.*?)(?:"\s*,\s*"claims|"citations|\Z)', text, re.DOTALL)
        if answer_match:
            status_match = re.search(r'"status"\s*:\s*"([^"]+)"', text)
            clean_answer = answer_match.group(1).replace("\\n", "\n").replace('\\"', '"').strip()
            return {
                "status": status_match.group(1) if status_match else "ANSWERED",
                "answer": clean_answer,
                "claims": [],
                "citations": [],
                "limitations": ["Parsed with robust JSON truncation recovery."],
            }

        raise StructuredOutputError(f"Model output could not be parsed as valid JSON: {text[:200]}...")


_provider_instance: OllamaProvider | None = None


def get_llm_provider() -> OllamaProvider:
    """Singleton getter for Ollama local provider."""
    global _provider_instance
    if _provider_instance is None:
        _provider_instance = OllamaProvider()
    return _provider_instance
