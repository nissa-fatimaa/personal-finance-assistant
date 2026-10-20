"""Optional OpenAI-compatible structured output; disabled without explicit setup."""

import json
from typing import TypeVar

import httpx
from pydantic import BaseModel, ValidationError

from app.config import get_settings

ModelT = TypeVar("ModelT", bound=BaseModel)


def is_configured() -> bool:
    settings = get_settings()
    return bool(settings.llm_base_url and settings.llm_api_key and settings.llm_model)


async def extract_structured(
    *,
    system_prompt: str,
    untrusted_text: str,
    response_model: type[ModelT],
) -> ModelT | None:
    """Try a strict JSON schema at most twice; failures always fall back offline."""
    settings = get_settings()
    if not (settings.llm_base_url and settings.llm_api_key and settings.llm_model):
        return None

    schema = response_model.model_json_schema()
    endpoint = settings.llm_base_url.rstrip("/") + "/chat/completions"
    headers = {
        "Authorization": f"Bearer {settings.llm_api_key.get_secret_value()}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": settings.llm_model,
        "temperature": 0,
        "max_tokens": 300,
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": response_model.__name__.lower(),
                "strict": True,
                "schema": schema,
            },
        },
        "messages": [
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": json.dumps(
                    {"untrusted_text": untrusted_text}, ensure_ascii=False
                ),
            },
        ],
    }

    async with httpx.AsyncClient(timeout=12) as client:
        for _attempt in range(2):
            try:
                response = await client.post(endpoint, headers=headers, json=payload)
                response.raise_for_status()
                content = response.json()["choices"][0]["message"]["content"]
                if not isinstance(content, str):
                    continue
                parsed = json.loads(content)
                return response_model.model_validate(parsed, strict=True)
            except (
                httpx.HTTPError,
                KeyError,
                IndexError,
                TypeError,
                ValueError,
                ValidationError,
            ):
                continue
    return None
