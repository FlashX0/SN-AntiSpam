"""Safe, bounded OCR helpers for Discord image attachments."""
from __future__ import annotations

from io import BytesIO
import logging
import os
from pathlib import Path

from PIL import Image, UnidentifiedImageError
import pytesseract

LOGGER = logging.getLogger(__name__)


def configure_tesseract() -> bool:
    """Configure pytesseract from PATH or common Windows installation paths."""
    configured = os.getenv("TESSERACT_CMD", "").strip()
    candidates = [configured] if configured else []
    candidates.extend(
        [
            r"C:\Program Files\Tesseract-OCR\tesseract.exe",
            r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
        ]
    )
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            pytesseract.pytesseract.tesseract_cmd = candidate
            return True
    try:
        pytesseract.get_tesseract_version()
        return True
    except pytesseract.TesseractNotFoundError:
        return False


def extract_text(image_bytes: bytes) -> str:
    """Return OCR text for an image, without writing untrusted uploads to disk."""
    try:
        with Image.open(BytesIO(image_bytes)) as image:
            image.load()
            # RGB avoids errors from palette/alpha modes in some screenshot formats.
            return pytesseract.image_to_string(image.convert("RGB"))
    except (UnidentifiedImageError, OSError) as exc:
        LOGGER.warning("Could not decode image for OCR: %s", exc)
        return ""
    except pytesseract.TesseractError as exc:
        LOGGER.warning("OCR failed: %s", exc)
        return ""
