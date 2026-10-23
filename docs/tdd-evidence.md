# TDD evidence: Discord honeypot detection

## User journeys

1. As a moderator, I want every human message in `type-here-to-get-kicked` to trigger enforcement so the channel acts as a honeypot.
2. As a moderator, I want known scam domains and promotion language detected in text or OCR output so fraudulent posts can be removed.
3. As a moderator, I want ordinary messages outside the trap ignored unless broad scanning is configured.

## RED evidence

Command: `./.venv/Scripts/python.exe -m pytest tests/test_detection.py -q`

Initial result: collection failed with `ModuleNotFoundError: No module named 'detector'`. This was the intended missing-implementation state.

## GREEN evidence

Command: `./.venv/Scripts/python.exe -m pytest --cov=detector --cov-report=term-missing`

Result: `5 passed in 0.04s`; detector coverage `97.78%`, exceeding the configured 80% threshold.

| # | Guarantee | Test | Type | Result |
|---|---|---|---|---|
| 1 | Honeypot channel matching is case-insensitive | `test_detects_trap_channel_case_insensitively` | unit | PASS |
| 2 | `rasowin[.]com` is normalized and detected | `test_detects_blacklisted_domain_and_normalizes_obfuscation` | unit | PASS |
| 3 | Fake giveaway, promo, USDT, and withdrawal language is detected | `test_detects_compound_fake_giveaway_language` | unit | PASS |
| 4 | Benign text outside the trap is not flagged | `test_benign_general_message_is_not_detected` | unit | PASS |
| 5 | OCR output takes the same signature-detection path | `test_ocr_text_uses_the_same_detection_rules` | unit | PASS |

## Environment verification

- Python virtual environment: Python 3.14.7
- Tesseract: `tesseract v5.4.0.20240606`, installed at `C:\Program Files\Tesseract-OCR\tesseract.exe`
- Source syntax check: `./.venv/Scripts/python.exe -m py_compile main.py detector.py ocr.py` completed successfully.

## Campaign-rule update (October 23, 2026)

### RED evidence

Command: `./.venv/Scripts/python.exe -m pytest tests/test_detection.py -q`

Result before implementation: `3 failed, 5 passed`. The new Muecox, `MONEY` promo-code, and `$2,500` amount assertions failed as intended.

### GREEN evidence

Command: `./.venv/Scripts/python.exe -m pytest --cov=detector --cov-report=term-missing`

Result after implementation: `8 passed in 0.05s`; detector coverage remained `97.78%`.

| # | Guarantee | Test | Type | Result |
|---|---|---|---|---|
| 6 | Muecox `.com` is normalized and detected, and `MONEY` works as a promo-code keyword | `test_detects_muecox_domain_and_money_promo_code` | unit | PASS |
| 7 | `$2,500 USDT` and `2,500 USD` formats are detected | `test_detects_2500_usdt_in_both_campaign_formats` | unit | PASS |
| 8 | Bare `Muecox`, Muecox `.net`/`.org`, and bare `Vyro` are detected | `test_detects_muecox_tlds_and_vyro_as_standalone_terms` | unit | PASS |

The bot was restarted and verified connected to Discord Gateway at `2026-10-23 16:40:07` and ready at `2026-10-23 16:40:09`.

## Audit-log channel update (October 23, 2026)

### RED evidence

Command: `./.venv/Scripts/python.exe -m pytest tests/test_audit_logging.py -q`

Result before implementation: import failed because `find_log_channel` and `build_enforcement_embed` did not yet exist.

### GREEN evidence

Command: `./.venv/Scripts/python.exe -m pytest -q`

Result after implementation: `11 passed`. The tests prove case-insensitive emoji-name matching, fallback to `botlogs`, and the permanent audit embed’s offender, action, source, reason, and UTC timestamp fields.

The restarted bot connected to Discord Gateway at `2026-10-23 16:58:28` and was ready at `2026-10-23 16:58:30`.

## Forwarded messages, server-wide scan & role hierarchy update (October 23, 2026)

### RED evidence

Command: `./.venv/Scripts/python.exe -m pytest tests/test_forwarded_messages.py -q`

Result before implementation: failed to collect due to missing `hierarchy_failure_message`, `iter_message_attachments`, and `snapshot_text`.

### GREEN evidence

Command: `./.venv/Scripts/python.exe -m pytest --cov=. --cov-report=term-missing`

Result after implementation: `18 passed in 0.69s`; total coverage reached `82.91%` (exceeding 80.0% requirement).

| # | Guarantee | Test | Type | Result |
|---|---|---|---|---|
| 9 | Direct and snapshot attachments are extracted together | `test_forwarded_snapshot_attachments_are_collected_with_direct_attachments` | unit | PASS |
| 10 | Snapshot inner text and embeds are inspected for scam signatures | `test_forwarded_snapshot_text_and_embeds_are_scanned_for_scam_signatures` | unit | PASS |
| 11 | Role hierarchy failure message provides actionable feedback | `test_role_hierarchy_failure_message_is_actionable` | unit | PASS |
| 12 | Role hierarchy failure logs to `⭐botlogs` and deletes message immediately | `test_enforce_handles_role_hierarchy_forbidden_and_deletes_message` | unit | PASS |
| 13 | Full server coverage enabled in environment | `test_scan_all_channels_setting_enforced` | unit | PASS |
| 14 | OCR recognizes all major image formats | `test_is_image_supports_broad_image_formats` | unit | PASS |
| 15 | OCR on forwarded attachment detects scam and triggers enforcement | `test_forwarded_snapshot_attachment_ocr_enforcement` | unit | PASS |

The bot was restarted and verified connected to Discord Gateway at `2026-10-23 18:06:49` and ready at `2026-10-23 18:06:51` as `SN - AntiSpam#4859 (id=1563179317746335764)`.

