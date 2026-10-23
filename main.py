"""Discord anti-spam honeypot bot.

Enable the Message Content intent in the Discord Developer Portal before running.
The bot role must have Manage Messages and Kick Members in the target server.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
import logging
import os
from typing import Any, Iterable

import discord
from dotenv import load_dotenv
from PIL import Image

from detector import DetectionEngine, DetectionResult
from ocr import configure_tesseract, extract_text

AUDIT_REASON = "Automated Honeypot / Scam Signature Detected"
IMAGE_EXTENSIONS: tuple[str, ...] = (
    ".png",
    ".jpg",
    ".jpeg",
    ".webp",
    ".gif",
    ".bmp",
    ".tiff",
    ".tif",
    ".jfif",
    ".ico",
    ".heic",
    ".heif",
    ".avif",
    ".ppm",
    ".pgm",
    ".pbm",
    ".pnm",
    ".tga",
)


@dataclass(frozen=True)
class Settings:
    token: str
    trap_channel_name: str
    action: str
    enforce_any_trap_message: bool
    scan_all_channels: bool
    max_image_bytes: int
    log_channel_name: str

    @classmethod
    def from_environment(cls) -> "Settings":
        load_dotenv()
        action = os.getenv("ENFORCEMENT_ACTION", "kick").casefold().strip()
        if action not in {"kick", "ban"}:
            raise ValueError("ENFORCEMENT_ACTION must be 'kick' or 'ban'.")
        return cls(
            token=os.getenv("DISCORD_BOT_TOKEN", "").strip(),
            trap_channel_name=os.getenv("TRAP_CHANNEL_NAME", "type-here-to-get-kicked").strip(),
            action=action,
            enforce_any_trap_message=os.getenv("ENFORCE_ANY_TRAP_MESSAGE", "true").casefold() == "true",
            scan_all_channels=os.getenv("SCAN_ALL_CHANNELS", "false").casefold() == "true",
            max_image_bytes=int(os.getenv("MAX_IMAGE_BYTES", str(8 * 1024 * 1024))),
            log_channel_name=os.getenv("LOG_CHANNEL_NAME", "⭐botlogs").strip(),
        )


def is_image(attachment: Any) -> bool:
    content_type = (getattr(attachment, "content_type", None) or "").casefold()
    if content_type.startswith("image/"):
        return True
    filename = (getattr(attachment, "filename", None) or "").casefold()
    return filename.endswith(IMAGE_EXTENSIONS)


def iter_message_attachments(message: Any) -> Iterable[Any]:
    for attachment in getattr(message, "attachments", None) or ():
        yield attachment
    for snapshot in getattr(message, "message_snapshots", None) or ():
        for attachment in getattr(snapshot, "attachments", None) or ():
            yield attachment


def _extract_embed_text(embed: Any) -> list[str]:
    chunks: list[str] = []
    title = getattr(embed, "title", None)
    if title:
        chunks.append(str(title))
    desc = getattr(embed, "description", None)
    if desc:
        chunks.append(str(desc))
    for field in getattr(embed, "fields", None) or ():
        name = getattr(field, "name", None)
        if name:
            chunks.append(str(name))
        value = getattr(field, "value", None)
        if value:
            chunks.append(str(value))
    footer = getattr(embed, "footer", None)
    if footer:
        footer_text = getattr(footer, "text", None)
        if footer_text:
            chunks.append(str(footer_text))
    author = getattr(embed, "author", None)
    if author:
        author_name = getattr(author, "name", None)
        if author_name:
            chunks.append(str(author_name))
    return chunks


def snapshot_text(snapshot: Any) -> str:
    chunks: list[str] = []
    content = getattr(snapshot, "content", None)
    if content:
        chunks.append(str(content))
    for embed in getattr(snapshot, "embeds", None) or ():
        chunks.extend(_extract_embed_text(embed))
    return "\n".join(chunks)


def hierarchy_failure_message(author: Any, action: str = "kick") -> str:
    mention = getattr(author, "mention", str(author))
    return (
        f"⚠️ Failed to {action} {mention} due to role hierarchy! Please move the bot role "
        "higher than the offender's roles."
    )


def combine(results: Iterable[DetectionResult]) -> DetectionResult:
    reasons: list[str] = []
    for result in results:
        reasons.extend(result.reasons)
    unique = tuple(dict.fromkeys(reasons))
    return DetectionResult(bool(unique), unique)


def find_log_channel(guild: discord.Guild, configured_name: str) -> discord.TextChannel | None:
    """Find the configured channel, with emoji and plain-name botlogs fallbacks."""
    candidate_names = (configured_name, "⭐botlogs", "botlogs")
    normalized_names = tuple(dict.fromkeys(name.casefold().strip() for name in candidate_names if name.strip()))
    for target_name in normalized_names:
        for channel in guild.text_channels:
            if channel.name.casefold().strip() == target_name:
                return channel
    return None


def build_enforcement_embed(
    offender: discord.Member,
    action: str,
    source_channel: discord.abc.GuildChannel,
    reasons: tuple[str, ...],
) -> discord.Embed:
    """Create a durable moderation audit record without pinging the offender."""
    action_label = action.capitalize()
    embed = discord.Embed(
        title=f"Honeypot enforcement: {action_label}",
        color=discord.Color.red(),
        timestamp=datetime.now(timezone.utc),
    )
    embed.add_field(
        name="Offender",
        value=f"{offender.mention} ({offender} / ID: `{offender.id}`)",
        inline=False,
    )
    embed.add_field(name="Action Taken", value=action_label, inline=True)
    embed.add_field(name="Source Channel", value=f"#{source_channel.name}", inline=True)
    embed.add_field(name="Reason / Trigger", value="\n".join(reasons)[:1024], inline=False)
    embed.set_footer(text="Automated Honeypot / Scam Signature Detected")
    return embed


class HoneypotBot(discord.Client):
    def __init__(self, settings: Settings) -> None:
        intents = discord.Intents.default()
        intents.message_content = True
        intents.guilds = True
        super().__init__(intents=intents)
        self.settings = settings
        self.detector = DetectionEngine(
            trap_channel_name=settings.trap_channel_name,
            enforce_any_trap_message=settings.enforce_any_trap_message,
        )
        self.ocr_ready = configure_tesseract()

    async def on_ready(self) -> None:
        logging.info("Connected as %s (id=%s)", self.user, self.user.id if self.user else "unknown")
        if not self.ocr_ready:
            logging.warning("Tesseract unavailable; image OCR is disabled, but text detection remains active.")

    async def on_message(self, message: discord.Message) -> None:
        if message.author.bot or message.guild is None or not isinstance(message.author, discord.Member):
            return
        if not isinstance(message.channel, (discord.abc.GuildChannel, discord.Thread)):
            return

        channel_name = getattr(message.channel, "name", "")
        is_trap = channel_name.casefold() == self.settings.trap_channel_name.casefold()
        if not is_trap and not self.settings.scan_all_channels:
            return

        text_results: list[DetectionResult] = [
            self.detector.inspect_text(message.content or "", channel_name)
        ]
        for embed in getattr(message, "embeds", None) or ():
            embed_text = "\n".join(_extract_embed_text(embed))
            if embed_text:
                text_results.append(self.detector.inspect_text(embed_text, channel_name))

        for snapshot in getattr(message, "message_snapshots", None) or ():
            snap_text = snapshot_text(snapshot)
            if snap_text:
                text_results.append(self.detector.inspect_text(snap_text, channel_name))

        ocr_results: list[DetectionResult] = []
        if self.ocr_ready:
            for attachment in iter_message_attachments(message):
                attachment_size = getattr(attachment, "size", None) or 0
                if is_image(attachment) and attachment_size <= self.settings.max_image_bytes:
                    try:
                        raw_image = await attachment.read(use_cached=True)
                    except discord.HTTPException as exc:
                        logging.warning("Could not download attachment %s: %s", getattr(attachment, "id", "unknown"), exc)
                        continue
                    ocr_text = await asyncio.to_thread(extract_text, raw_image)
                    if ocr_text:
                        ocr_results.append(self.detector.inspect_ocr_text(ocr_text, channel_name))

        result = combine([*text_results, *ocr_results])
        if result.detected:
            await self.enforce(message, result)

    async def send_audit_log(
        self,
        message: discord.Message,
        action: str,
        reasons: tuple[str, ...],
    ) -> None:
        if message.guild is None:
            return
        log_channel = find_log_channel(message.guild, self.settings.log_channel_name)
        if log_channel is None:
            logging.warning(
                "Audit log channel %r was not found in guild %s", self.settings.log_channel_name, message.guild.id
            )
            return
        try:
            await log_channel.send(
                embed=build_enforcement_embed(message.author, action, message.channel, reasons),
                allowed_mentions=discord.AllowedMentions.none(),
            )
        except discord.Forbidden:
            logging.warning("Missing permission to send an audit log in #%s", log_channel.name)
        except discord.HTTPException as exc:
            logging.warning("Failed to send audit log in #%s: %s", log_channel.name, exc)

    async def send_hierarchy_log(
        self,
        message: discord.Message,
        action: str,
    ) -> None:
        if message.guild is None:
            return
        log_channel = find_log_channel(message.guild, self.settings.log_channel_name)
        if log_channel is None:
            logging.warning(
                "Audit log channel %r was not found in guild %s", self.settings.log_channel_name, message.guild.id
            )
            return
        try:
            await log_channel.send(
                hierarchy_failure_message(message.author, action),
                allowed_mentions=discord.AllowedMentions.none(),
            )
        except discord.Forbidden:
            logging.warning("Missing permission to send hierarchy warning in #%s", log_channel.name)
        except discord.HTTPException as exc:
            logging.warning("Failed to send hierarchy warning in #%s: %s", log_channel.name, exc)

    async def enforce(self, message: discord.Message, result: DetectionResult) -> None:
        reason_detail = "; ".join(result.reasons[:5])
        audit_reason = f"{AUDIT_REASON}: {reason_detail}"[:512]

        action_succeeded = False
        try:
            if self.settings.action == "ban":
                await message.author.ban(reason=audit_reason, delete_message_seconds=0)
            else:
                await message.author.kick(reason=audit_reason)
            action_succeeded = True
        except discord.Forbidden:
            logging.error("Missing permission to %s %s due to role hierarchy", self.settings.action, message.author)
            await self.send_hierarchy_log(message, self.settings.action)
        except discord.HTTPException as exc:
            logging.warning("Failed to %s %s: %s", self.settings.action, message.author, exc)
        finally:
            try:
                await message.delete()
            except discord.NotFound:
                pass
            except discord.Forbidden:
                channel_name = getattr(message.channel, "name", "unknown")
                logging.error("Missing Manage Messages permission in #%s", channel_name)
            except discord.HTTPException as exc:
                logging.warning("Failed to delete message %s: %s", message.id, exc)

        if action_succeeded:
            await self.send_audit_log(message, self.settings.action, result.reasons)

        outcome = "completed" if action_succeeded else "attempted"
        alert = (
            f"⚠️ A honeypot/scam signature was detected. The message was removed and "
            f"enforcement was {outcome}. Reason: `{reason_detail}`"
        )
        try:
            await message.channel.send(alert, delete_after=10, allowed_mentions=discord.AllowedMentions.none())
        except discord.HTTPException as exc:
            logging.warning("Failed to send auto-expiring alert: %s", exc)


def main() -> None:
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    settings = Settings.from_environment()
    if not settings.token:
        raise SystemExit("DISCORD_BOT_TOKEN is empty. Add it to .env before starting the bot.")
    HoneypotBot(settings).run(settings.token, log_handler=None)


if __name__ == "__main__":
    main()
