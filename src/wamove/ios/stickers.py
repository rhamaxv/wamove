"""Favourite stickers on the iPhone.

WhatsApp for iOS lists favourites in `Sticker.sqlite` as `ZWACDSTICKER` rows without a sticker pack
(`ZSTICKERPACK` NULL, flags 256) and keeps the image at `stickers/no-sticker-pack/<uuid>.webp` inside
the app group. Observed on iOS 27 / WhatsApp 25.x; the layout is Core Data, so Z_MAX must follow.
"""
from __future__ import annotations

import sqlite3
import uuid
from collections.abc import Callable, Iterable
from pathlib import Path

from ..android.stickers import Favorite

STICKER_DB = "Sticker.sqlite"
FOLDER = "no-sticker-pack"
FAVORITE_FLAGS = 256
ENTITY = "WACDSticker"


class StickerError(Exception):
    pass


def import_favorites(database: Path, favorites: Iterable[Favorite],
                     put_file: Callable[[str, Path], None]) -> tuple[int, int]:
    """Add favourites to the iPhone's sticker database. Returns (added, already_there).

    `put_file(relative_path, source)` stores each image inside the backup; the path is relative to
    the app group root, e.g. `stickers/no-sticker-pack/<uuid>.webp`.
    """
    conn = sqlite3.connect(database)
    try:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "ZWACDSTICKER" not in tables or "Z_PRIMARYKEY" not in tables:
            raise StickerError("Sticker.sqlite does not look like WhatsApp's sticker database")
        columns = {r[1] for r in conn.execute("PRAGMA table_info(ZWACDSTICKER)")}
        needed = {"ZSTICKERPACK", "ZFLAGS", "ZFILEHASH", "ZRELATIVEIMAGEPATH", "ZFILELENGTH", "ZMIMETYPE"}
        if not needed <= columns:
            raise StickerError("Sticker.sqlite has a layout wamove does not know")
        row = conn.execute("SELECT Z_ENT, Z_MAX FROM Z_PRIMARYKEY WHERE Z_NAME=?", (ENTITY,)).fetchone()
        if row is None:
            raise StickerError(f"Sticker.sqlite has no {ENTITY} entity")
        entity, maximum = row[0], row[1] or 0
        highest = conn.execute("SELECT COALESCE(MAX(Z_PK), 0) FROM ZWACDSTICKER").fetchone()[0]
        next_pk = max(maximum, highest) + 1
        present = {r[0] for r in conn.execute("SELECT ZFILEHASH FROM ZWACDSTICKER WHERE ZSTICKERPACK IS NULL")}
        sort = conn.execute("SELECT COALESCE(MAX(ZSORT), -1) FROM ZWACDSTICKER WHERE ZSTICKERPACK IS NULL").fetchone()[0]
        added = skipped = 0
        for favorite in favorites:
            if favorite.file_hash in present:
                skipped += 1
                continue
            relative = f"{FOLDER}/{uuid.uuid4()}.webp"
            sort += 1
            values = {
                "Z_PK": next_pk, "Z_ENT": entity, "Z_OPT": 2,
                "ZFILELENGTH": favorite.size, "ZFLAGS": FAVORITE_FLAGS, "ZHEIGHT": 64, "ZWIDTH": 64, "ZSORT": sort,
                "ZSTICKERPACK": None, "ZFILEHASH": favorite.file_hash, "ZMIMETYPE": "image/webp",
                "ZRELATIVEIMAGEPATH": relative, "ZENCFILEHASH": favorite.enc_hash,
                "ZDIRECTPATH": favorite.direct_path, "ZURL": favorite.url, "ZMEDIAKEY": favorite.media_key,
            }
            values = {k: v for k, v in values.items() if k in columns or k in ("Z_PK", "Z_ENT", "Z_OPT")}
            conn.execute(f"INSERT INTO ZWACDSTICKER ({', '.join(values)}) VALUES ({', '.join('?' for _ in values)})",
                         list(values.values()))
            put_file(f"stickers/{relative}", favorite.path)
            present.add(favorite.file_hash)
            next_pk += 1
            added += 1
        conn.execute("UPDATE Z_PRIMARYKEY SET Z_MAX=? WHERE Z_NAME=?", (next_pk - 1, ENTITY))
        conn.commit()
        return added, skipped
    finally:
        conn.close()
