"""Text and OCR signature detection for the Discord honeypot."""
from __future__ import annotations

from dataclasses import dataclass
import re
from urllib.parse import urlparse


BLACKLISTED_DOMAINS = frozenset(
    {
        "rasowin.com",
        "rasowin.net",
        "rasowin.org",
        "muecox.com",
        "muecox.net",
        "muecox.org",
    }
)

# These phrases indicate a scam promotion when present individually. Keep this list
# deliberately specific to reduce false positives in normal server discussion.
SCAM_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("mrbeast-crypto-giveaway", re.compile(r"\bmr\s*beast\b.*\b(?:crypto|giveaway)\b|\b(?:crypto|giveaway)\b.*\bmr\s*beast\b", re.I)),
    ("casino-promotion", re.compile(r"\b(?:casino|slots|betting)\b.{0,80}\b(?:promo|bonus|code|claim)\b|\b(?:promo|bonus|code|claim)\b.{0,80}\b(?:casino|slots|betting)\b", re.I)),
    ("bonus-promo-code", re.compile(r"\b(?:bonus|money)\b.{0,50}\b(?:code|promo|claim)\b|\b(?:code|promo)\b.{0,50}\b(?:bonus|money)\b", re.I)),
    ("muecox-promotion", re.compile(r"\bmuecox\b", re.I)),
    ("vyro-promotion", re.compile(r"\bvyro\b", re.I)),
    ("fake-withdrawal-success", re.compile(r"\bwithdrawal\s+(?:was\s+)?successful\b|\bwithdrawal\s+success\b", re.I)),
    ("usdt-withdrawal-lure", re.compile(r"\$?\s*2\s*,?\s*(?:500|700)\s*usdt\b|\b2\s*,?\s*(?:500|700)\s*(?:\$|usd|usdt)\b", re.I)),
)


@dataclass(frozen=True)
class DetectionResult:
    """An immutable result so audit reasons can be assembled consistently."""

    detected: bool
    reasons: tuple[str, ...]


class DetectionEngine:
    """Matches configured scam signatures and the dedicated honeypot channel."""

    def __init__(self, trap_channel_name: str, enforce_any_trap_message: bool = True) -> None:
        self.trap_channel_name = trap_channel_name.casefold().strip()
        self.enforce_any_trap_message = enforce_any_trap_message

    def inspect_text(self, text: str, channel_name: str) -> DetectionResult:
        reasons: list[str] = []
        normalized_text = self._normalize(text)

        if self.enforce_any_trap_message and channel_name.casefold().strip() == self.trap_channel_name:
            reasons.append("trap-channel-message")

        for domain in self._extract_domains(normalized_text):
            if domain in BLACKLISTED_DOMAINS:
                reasons.append(f"blacklisted-domain:{domain}")

        for label, pattern in SCAM_PATTERNS:
            if pattern.search(normalized_text):
                reasons.append(f"scam-keyword:{label}")

        unique_reasons = tuple(dict.fromkeys(reasons))
        return DetectionResult(detected=bool(unique_reasons), reasons=unique_reasons)

    def inspect_ocr_text(self, text: str, channel_name: str) -> DetectionResult:
        result = self.inspect_text(text, channel_name)
        if not result.detected:
            return result
        return DetectionResult(True, ("source:ocr", *result.reasons))

    @staticmethod
    def _normalize(text: str) -> str:
        # Makes common obfuscations such as rasowin[.]com visible to URL matching.
        return text.replace("[.]", ".").replace("(.)", ".").replace(" ", " ")

    @staticmethod
    def _extract_domains(text: str) -> set[str]:
        candidates = re.findall(r"(?:https?://)?(?:www\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)+", text.casefold())
        domains: set[str] = set()
        for candidate in candidates:
            parsed = urlparse(candidate if "://" in candidate else f"//{candidate}")
            host = (parsed.hostname or "").casefold().removeprefix("www.")
            if host:
                domains.add(host)
        return domains
