"""Python-computed insight facts with verified optional wording."""

import re
from decimal import Decimal, ROUND_HALF_UP

from pydantic import BaseModel, ConfigDict, Field

from app import llm, money

_PLACEHOLDER_RE = re.compile(r"\{([a-z_]+)\}")
_NUMBER_WORD_RE = re.compile(
    r"\b(?:zero|one|two|three|four|five|six|seven|eight|nine|ten|"
    r"eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|"
    r"eighteen|nineteen|twenty|thirty|forty|fifty|sixty|seventy|"
    r"eighty|ninety|hundred|thousand|million|half|double|triple|"
    r"twice|first|second|third)\b",
    re.IGNORECASE,
)


class WordingResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    wording: str = Field(min_length=1, max_length=500)


def verify_wording(wording: str, expected: set[str]) -> bool:
    """Reject untrusted wording that invents figures or changes placeholders."""
    placeholders = _PLACEHOLDER_RE.findall(wording)
    if set(placeholders) != expected:
        return False
    without_placeholders = _PLACEHOLDER_RE.sub("", wording)
    return not any(char.isdigit() for char in without_placeholders) and not bool(
        _NUMBER_WORD_RE.search(without_placeholders)
    )


def compute_facts(dashboard: dict) -> list[dict]:
    """Select only current-period categories over pace using Python-calculated data."""
    if dashboard.get("days_left", 0) <= 0:
        return []
    result = []
    for category in dashboard.get("categories", []):
        raw_pace = category.get("pace")
        daily_cap = category.get("daily_cap_minor")
        if (
            raw_pace is None
            or daily_cap is None
            or category.get("spent_minor") is None
            or category.get("limit_minor", 0) <= 0
        ):
            continue
        pace = Decimal(str(raw_pace))
        if pace <= Decimal("1.05"):
            continue
        pace_percent = int(
            ((pace - 1) * 100).quantize(Decimal("1"), rounding=ROUND_HALF_UP)
        )
        result.append(
            {
                "category": str(category["name"])[:100],
                "spent_minor": int(category["spent_minor"]),
                "limit_minor": int(category["limit_minor"]),
                "pace_percent": pace_percent,
                "daily_cap_minor": int(daily_cap),
                "currency": str(category["currency"]).upper(),
                "days_left": int(dashboard.get("days_left", 1)),
            }
        )
    return result


def _template() -> str:
    return (
        "Your {category} spending is above its planned pace. "
        "Keeping to {daily_cap} each day for {days_left} more days may help you get back on track "
        "from {pace_percent}% above pace."
    )


async def _verified_wording(*, ai_consent: bool) -> tuple[str, str]:
    expected = {"category", "daily_cap", "days_left", "pace_percent"}
    if ai_consent and llm.is_configured():
        result = await llm.extract_structured(
            system_prompt=(
                "Write one friendly sentence about a budget category running above pace. "
                "Use each provided placeholder exactly, and do not write digits or number words. "
                "Return strict JSON with one wording field."
            ),
            untrusted_text=(
                "topic: budget_pace\n"
                "required placeholders: {category}, {daily_cap}, {days_left}, {pace_percent}"
            ),
            response_model=WordingResponse,
        )
        if result and verify_wording(result.wording, expected):
            return result.wording, "llm"
    return _template(), "template"


async def build_insights(dashboard: dict, *, ai_consent: bool) -> dict:
    facts = compute_facts(dashboard)
    insights = []
    for fact in facts:
        wording, source = await _verified_wording(ai_consent=ai_consent)
        rendered = wording.format(
            category=fact["category"],
            daily_cap=money.fmt(fact["daily_cap_minor"], fact["currency"]),
            days_left=fact["days_left"],
            pace_percent=fact["pace_percent"],
        )
        insights.append(
            {
                "kind": "budget_pace",
                "source": source,
                "wording": rendered,
                "facts": fact,
            }
        )
    return {"month": dashboard["month"], "insights": insights}
