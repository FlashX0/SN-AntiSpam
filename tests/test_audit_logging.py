from __future__ import annotations

from dataclasses import dataclass
from datetime import timezone

from main import build_enforcement_embed, find_log_channel


@dataclass
class FakeChannel:
    name: str


@dataclass
class FakeGuild:
    text_channels: list[FakeChannel]


@dataclass
class FakeUser:
    id: int
    mention: str

    def __str__(self) -> str:
        return "Scammer#1234"


def test_finds_configured_emoji_log_channel_case_insensitively() -> None:
    expected = FakeChannel("⭐BOTLOGS")
    guild = FakeGuild([FakeChannel("general"), expected, FakeChannel("botlogs")])

    assert find_log_channel(guild, "⭐botlogs") is expected


def test_falls_back_to_plain_botlogs_channel() -> None:
    expected = FakeChannel("BoTLoGs")

    assert find_log_channel(FakeGuild([expected]), "⭐botlogs") is expected


def test_enforcement_embed_contains_permanent_audit_details() -> None:
    embed = build_enforcement_embed(
        offender=FakeUser(id=123456789, mention="<@123456789>"),
        action="ban",
        source_channel=FakeChannel("type-here-to-get-kicked"),
        reasons=("blacklisted-domain:muecox.com", "source:ocr"),
    )
    fields = {field.name: field.value for field in embed.fields}

    assert embed.title == "Honeypot enforcement: Ban"
    assert "<@123456789>" in fields["Offender"]
    assert "123456789" in fields["Offender"]
    assert fields["Source Channel"] == "#type-here-to-get-kicked"
    assert "muecox.com" in fields["Reason / Trigger"]
    assert embed.timestamp is not None
    assert embed.timestamp.tzinfo == timezone.utc
