from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import discord

from detector import DetectionEngine, DetectionResult
from main import (
    HoneypotBot,
    Settings,
    hierarchy_failure_message,
    is_image,
    iter_message_attachments,
    snapshot_text,
)


def test_forwarded_snapshot_attachments_are_collected_with_direct_attachments() -> None:
    direct = SimpleNamespace(id=1, filename="direct.png", content_type="image/png")
    forwarded = SimpleNamespace(id=2, filename="forwarded.tiff", content_type=None)
    snapshot = SimpleNamespace(attachments=[forwarded], content="", embeds=[])
    message = SimpleNamespace(attachments=[direct], message_snapshots=[snapshot])

    attachments = list(iter_message_attachments(message))

    assert attachments == [direct, forwarded]
    assert is_image(forwarded) is True


def test_forwarded_snapshot_text_and_embeds_are_scanned_for_scam_signatures() -> None:
    embed = discord.Embed(title="Muecox promotion", description="Claim $2,500 USDT now")
    snapshot = SimpleNamespace(attachments=[], content="MONEY promo code", embeds=[embed])
    scanner = DetectionEngine("type-here-to-get-kicked")

    result = scanner.inspect_text(snapshot_text(snapshot), "general")

    assert "scam-keyword:muecox-promotion" in result.reasons
    assert "scam-keyword:usdt-withdrawal-lure" in result.reasons
    assert "scam-keyword:bonus-promo-code" in result.reasons


def test_role_hierarchy_failure_message_is_actionable() -> None:
    author = SimpleNamespace(mention="<@123456789>")

    message = hierarchy_failure_message(author, "kick")

    assert message == (
        "⚠️ Failed to kick <@123456789> due to role hierarchy! Please move the bot role "
        "higher than the offender's roles."
    )


def test_enforce_handles_role_hierarchy_forbidden_and_deletes_message() -> None:
    async def run_scenario() -> None:
        settings = Settings(
            token="test-token",
            trap_channel_name="trap",
            action="kick",
            enforce_any_trap_message=True,
            scan_all_channels=True,
            max_image_bytes=8 * 1024 * 1024,
            log_channel_name="⭐botlogs",
        )
        bot = HoneypotBot(settings)

        log_channel = MagicMock(spec=discord.TextChannel)
        log_channel.name = "⭐botlogs"
        log_channel.send = AsyncMock()

        guild = MagicMock(spec=discord.Guild)
        guild.text_channels = [log_channel]

        author = MagicMock(spec=discord.Member)
        author.mention = "<@123456789>"

        forbidden_response = MagicMock()
        forbidden_response.status = 403
        forbidden_response.reason = "Forbidden"
        author.kick = AsyncMock(side_effect=discord.Forbidden(forbidden_response, "Missing Permissions"))

        source_channel = MagicMock(spec=discord.TextChannel)
        source_channel.name = "general"
        source_channel.send = AsyncMock()

        message = MagicMock(spec=discord.Message)
        message.guild = guild
        message.author = author
        message.channel = source_channel
        message.delete = AsyncMock()

        result = DetectionResult(True, ("scam-keyword:vyro-promotion",))
        await bot.enforce(message, result)

        # Message must be deleted immediately even if kick fails
        assert message.delete.called is True
        # Error must be logged to ⭐botlogs with actionable hierarchy warning
        assert log_channel.send.called is True
        log_args, _ = log_channel.send.call_args
        assert log_args[0] == (
            "⚠️ Failed to kick <@123456789> due to role hierarchy! Please move the bot role "
            "higher than the offender's roles."
        )

    asyncio.run(run_scenario())


def test_scan_all_channels_setting_enforced() -> None:
    settings = Settings.from_environment()
    assert settings.scan_all_channels is True


def test_is_image_supports_broad_image_formats() -> None:
    supported_formats = [
        "image.png",
        "photo.jpg",
        "photo.jpeg",
        "graphic.webp",
        "animation.gif",
        "bitmap.bmp",
        "scan.tiff",
        "scan.tif",
        "capture.jfif",
        "icon.ico",
        "modern.avif",
        "UPPERCASE.TIFF",
        "UPPERCASE.PNG",
    ]
    for filename in supported_formats:
        att = SimpleNamespace(filename=filename, content_type=None)
        assert is_image(att) is True, f"Expected {filename} to be recognized as image"

    non_images = ["document.pdf", "script.py", "archive.zip", "data.txt"]
    for filename in non_images:
        att = SimpleNamespace(filename=filename, content_type=None)
        assert is_image(att) is False, f"Expected {filename} to not be recognized as image"


def test_forwarded_snapshot_attachment_ocr_enforcement() -> None:
    async def run_scenario() -> None:
        settings = Settings(
            token="test-token",
            trap_channel_name="trap",
            action="kick",
            enforce_any_trap_message=True,
            scan_all_channels=True,
            max_image_bytes=8 * 1024 * 1024,
            log_channel_name="⭐botlogs",
        )
        bot = HoneypotBot(settings)
        bot.enforce = AsyncMock()
        bot.ocr_ready = True

        channel = MagicMock(spec=discord.TextChannel)
        channel.name = "public-chat"
        guild = MagicMock(spec=discord.Guild)
        author = MagicMock(spec=discord.Member)
        author.bot = False

        forwarded_att = MagicMock(spec=discord.Attachment)
        forwarded_att.id = 42
        forwarded_att.filename = "forwarded_promo.tiff"
        forwarded_att.content_type = "image/tiff"
        forwarded_att.size = 1024
        forwarded_att.read = AsyncMock(return_value=b"fake-tiff-bytes")

        snapshot = MagicMock()
        snapshot.attachments = [forwarded_att]
        snapshot.content = "forwarded notice"
        snapshot.embeds = []

        message = MagicMock(spec=discord.Message)
        message.author = author
        message.guild = guild
        message.channel = channel
        message.content = "look at this forward"
        message.embeds = []
        message.attachments = []
        message.message_snapshots = [snapshot]

        with patch("main.extract_text", return_value="Claim 2,500 USDT now on muecox.com"):
            await bot.on_message(message)

        assert bot.enforce.called is True
        result = bot.enforce.call_args[0][1]
        assert result.detected is True
        assert "source:ocr" in result.reasons
        assert "scam-keyword:usdt-withdrawal-lure" in result.reasons
        assert "blacklisted-domain:muecox.com" in result.reasons

    asyncio.run(run_scenario())
