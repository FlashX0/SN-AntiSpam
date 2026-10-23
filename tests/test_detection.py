from __future__ import annotations

from detector import DetectionEngine


def engine() -> DetectionEngine:
    return DetectionEngine(
        trap_channel_name="type-here-to-get-kicked",
        enforce_any_trap_message=True,
    )


def test_detects_trap_channel_case_insensitively() -> None:
    result = engine().inspect_text("Hello", "TYPE-HERE-TO-GET-KICKED")

    assert result.detected is True
    assert "trap-channel-message" in result.reasons


def test_detects_blacklisted_domain_and_normalizes_obfuscation() -> None:
    result = engine().inspect_text("Claim now: https://rasowin[.]com/bonus", "general")

    assert result.detected is True
    assert "blacklisted-domain:rasowin.com" in result.reasons


def test_detects_compound_fake_giveaway_language() -> None:
    result = engine().inspect_text(
        "MrBeast crypto giveaway: BONUS code for $2,700 USDT withdrawal success", "general"
    )

    assert result.detected is True
    assert any(reason.startswith("scam-keyword:") for reason in result.reasons)


def test_detects_muecox_domain_and_money_promo_code() -> None:
    result = engine().inspect_text(
        "Go to muecox[.]com and enter the special promo code: MONEY", "general"
    )

    assert result.detected is True
    assert "blacklisted-domain:muecox.com" in result.reasons
    assert "scam-keyword:bonus-promo-code" in result.reasons


def test_detects_2500_usdt_in_both_campaign_formats() -> None:
    usdt_first = engine().inspect_text("Withdrawal successful: $2,500 USDT", "general")
    currency_last = engine().inspect_text("Your reward is 2,500 USD", "general")

    assert "scam-keyword:usdt-withdrawal-lure" in usdt_first.reasons
    assert "scam-keyword:usdt-withdrawal-lure" in currency_last.reasons


def test_detects_muecox_tlds_and_vyro_as_standalone_terms() -> None:
    muecox = engine().inspect_text("Muecox", "general")
    muecox_net = engine().inspect_text("muecox.net", "general")
    muecox_org = engine().inspect_text("muecox.org", "general")
    vyro = engine().inspect_text("Vyro", "general")

    assert "scam-keyword:muecox-promotion" in muecox.reasons
    assert "blacklisted-domain:muecox.net" in muecox_net.reasons
    assert "blacklisted-domain:muecox.org" in muecox_org.reasons
    assert "scam-keyword:vyro-promotion" in vyro.reasons


def test_benign_general_message_is_not_detected() -> None:
    result = engine().inspect_text("The team meeting starts at 10 AM.", "general")

    assert result.detected is False
    assert result.reasons == ()


def test_ocr_text_uses_the_same_detection_rules() -> None:
    result = engine().inspect_ocr_text("Vyro casino promo - Withdrawal Success", "general")

    assert result.detected is True
    assert "source:ocr" in result.reasons
