"""Small OpenAI runtime used by the lab instead of Google ADK.

It intentionally exposes a minimal agent/runner/plugin interface so the rest of
this security lab can focus on guardrails, HITL and observability.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any, AsyncIterator



@dataclass
class Part:
    text: str = ""

    @classmethod
    def from_text(cls, text: str) -> "Part":
        return cls(text=text)


@dataclass
class Content:
    role: str | None = None
    parts: list[Part] = field(default_factory=list)


@dataclass
class ModelResponse:
    content: Content


@dataclass
class Event:
    content: Content


class BasePlugin:
    def __init__(self, name: str = "plugin") -> None:
        self.name = name


class Agent:
    def __init__(self, *, model: str, name: str, instruction: str) -> None:
        self.model = model
        self.name = name
        self.instruction = instruction


class _SessionService:
    async def create_session(self, **_: Any) -> None:
        return None


class Runner:
    def __init__(self, *, agent: Agent, app_name: str, plugins: list[Any] | None = None) -> None:
        self.agent = agent
        self.app_name = app_name
        self.plugins = plugins or []
        self.session_service = _SessionService()

    @staticmethod
    def _text(content: Content | None) -> str:
        if content is None:
            return ""
        return "".join(part.text for part in content.parts if getattr(part, "text", None))

    async def run_async(
        self,
        *,
        user_id: str,
        session_id: str,
        new_message: Content,
    ) -> AsyncIterator[Event]:
        del user_id, session_id

        for plugin in self.plugins:
            callback = getattr(plugin, "on_user_message_callback", None)
            if callback is not None:
                blocked = await callback(invocation_context=None, user_message=new_message)
                if blocked is not None:
                    yield Event(content=blocked)
                    return

        try:
            from openai import AsyncOpenAI
        except ImportError as exc:
            raise RuntimeError("Missing dependency: pip install openai") from exc
        client = AsyncOpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
        result = await client.responses.create(
            model=self.agent.model,
            instructions=self.agent.instruction,
            input=self._text(new_message),
        )
        response = ModelResponse(
            content=Content(role="assistant", parts=[Part.from_text(result.output_text or "")])
        )

        for plugin in self.plugins:
            callback = getattr(plugin, "after_model_callback", None)
            if callback is not None:
                maybe_response = await callback(callback_context=None, llm_response=response)
                if maybe_response is not None:
                    response = maybe_response

        yield Event(content=response.content)


types = SimpleNamespace(Content=Content, Part=Part)
base_plugin = SimpleNamespace(BasePlugin=BasePlugin)
llm_agent = SimpleNamespace(LlmAgent=Agent)
runners = SimpleNamespace(InMemoryRunner=Runner)
InvocationContext = object
