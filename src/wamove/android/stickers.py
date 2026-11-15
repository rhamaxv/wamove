"""Favourite stickers on Android.

WhatsApp keeps an encrypted copy of every favourite sticker in `Backups/Stickers`, one `.webp.crypt15`
file per sticker, named after the sticker's file hash (base64 SHA-256 with `/` written as `-`). The
same stickers usually also sit unencrypted in `Media/WhatsApp Stickers`, so a favourite can be
recovered either by decrypting its backup copy or by finding a media file with the same hash.
"""
from __future__ import annotations

import base64
import hashlib
import os
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from . import crypt15

BACKUP_SUFFIX = ".webp.crypt15"


@dataclass
class Favorite:
    file_hash: str            # base64 SHA-256 of the .webp bytes, as WhatsApp stores it
    path: Path                # readable .webp on this computer
    size: int
    media_key: bytes | None = None
    enc_hash: str | None = None
    direct_path: str | None = None
    url: str | None = None


def wanted_hashes(backup_dir: Path) -> dict[str, Path]:
    """file hash -> encrypted backup file, for every favourite WhatsApp backed up."""
    found: dict[str, Path] = {}
    if not backup_dir.is_dir():
        return found
    for item in backup_dir.iterdir():
        if item.name.endswith(BACKUP_SUFFIX):
            found[item.name[:-len(BACKUP_SUFFIX)].replace("-", "/")] = item
    return found


def file_hash(path: Path) -> str:
    return base64.b64encode(hashlib.sha256(path.read_bytes()).digest()).decode()


def decrypt_backups(backup_dir: Path, out_dir: Path, key: bytes) -> dict[str, Path]:
    """Decrypt every backed-up favourite with the 64-digit key. Returns file hash -> plain .webp."""
    out_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    plain: dict[str, Path] = {}
    aes = crypt15.derive_aes_key(key)
    for digest, enc in wanted_hashes(backup_dir).items():
        try:
            data = crypt15.decrypt_raw(enc.read_bytes(), aes)
        except crypt15.Crypt15Error:
            continue
        target = out_dir / (enc.name[:-len(".crypt15")].replace("/", "-"))
        target.write_bytes(data)
        plain[digest] = target
    return plain


def match_media(backup_dir: Path, media_dir: Path) -> dict[str, Path]:
    """Without the key: find favourites among the unencrypted sticker files by content hash."""
    wanted = wanted_hashes(backup_dir)
    found: dict[str, Path] = {}
    if not wanted or not media_dir.is_dir():
        return found
    for directory, _, names in os.walk(media_dir):
        for name in names:
            path = Path(directory) / name
            try:
                digest = file_hash(path)
            except OSError:
                continue
            if digest in wanted and digest not in found:
                found[digest] = path
            if len(found) == len(wanted):
                return found
    return found


def media_details(msgstore: Path, hashes: set[str]) -> dict[str, tuple]:
    """Upload details WhatsApp recorded for these stickers when they went through a chat."""
    if not msgstore.is_file() or not hashes:
        return {}
    conn = sqlite3.connect(f"{msgstore.resolve().as_uri()}?mode=ro", uri=True)
    try:
        columns = {r[1] for r in conn.execute("PRAGMA table_info(message_media)")}
        if not {"file_hash", "media_key", "direct_path", "message_url", "enc_file_hash"} <= columns:
            return {}
        details: dict[str, tuple] = {}
        for row in conn.execute("SELECT file_hash, media_key, direct_path, message_url, enc_file_hash FROM message_media "
                                "WHERE file_hash IS NOT NULL AND mime_type LIKE 'image/webp%'"):
            if row[0] in hashes and row[0] not in details:
                details[row[0]] = row[1:]
        return details
    finally:
        conn.close()


def favorites(backup_dir: Path, plain_dir: Path, media_dir: Path, msgstore: Path) -> list[Favorite]:
    """Every favourite that can be read on this computer: decrypted copies first, media files second."""
    files: dict[str, Path] = {}
    if plain_dir.is_dir():
        for item in plain_dir.glob("*.webp"):
            files[item.name[:-len(".webp")].replace("-", "/")] = item
    missing = set(wanted_hashes(backup_dir)) - set(files)
    if missing:
        for digest, path in match_media(backup_dir, media_dir).items():
            files.setdefault(digest, path)
    details = media_details(msgstore, set(files))
    result = []
    for digest, path in files.items():
        media_key, direct_path, url, enc_hash = details.get(digest, (None, None, None, None))
        result.append(Favorite(digest, path, path.stat().st_size,
                               media_key=bytes(media_key) if media_key else None, enc_hash=enc_hash,
                               direct_path=direct_path, url=url))
    return result
