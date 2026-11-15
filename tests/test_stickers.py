"""Favourite stickers: Android backup copies, hash matching, and the iPhone sticker database."""
from __future__ import annotations

import base64
import hashlib
import sqlite3
import zlib
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from wamove.android import crypt15
from wamove.android import stickers as android
from wamove.ios import stickers as ios

KEY = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
SCHEMA = (Path(__file__).parent / "sticker_schema.sql").read_text()


def webp(seed: int) -> bytes:
    return b"RIFF\x00\x00\x00\x00WEBPVP8 " + bytes([seed]) * 40


def b64hash(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode()


def encrypt_raw(plain: bytes, key: bytes) -> bytes:
    iv = bytes(range(16))
    header = b"\x0a\x10" + iv  # one length-delimited protobuf field holding the IV
    body = AESGCM(crypt15.derive_aes_key(key)).encrypt(iv, zlib.compress(plain), None)
    return bytes([len(header)]) + header + body


def make_backup_dir(tmp_path: Path, key: bytes, seeds) -> tuple[Path, dict[str, bytes]]:
    backups = tmp_path / "Backups" / "Stickers"
    backups.mkdir(parents=True)
    plain: dict[str, bytes] = {}
    for seed in seeds:
        data = webp(seed)
        digest = b64hash(data)
        (backups / f"{digest.replace('/', '-')}.webp.crypt15").write_bytes(encrypt_raw(data, key))
        plain[digest] = data
    return backups, plain


def test_decrypt_backups_with_key(tmp_path: Path) -> None:
    key = crypt15.parse_key(KEY)
    backups, plain = make_backup_dir(tmp_path, key, range(3))
    out = android.decrypt_backups(backups, tmp_path / "plain", key)
    assert set(out) == set(plain)
    for digest, path in out.items():
        assert path.read_bytes() == plain[digest]


def test_match_media_without_key(tmp_path: Path) -> None:
    key = crypt15.parse_key(KEY)
    backups, plain = make_backup_dir(tmp_path, key, range(4))
    media = tmp_path / "Media" / "WhatsApp Stickers"
    media.mkdir(parents=True)
    for i, (digest, data) in enumerate(plain.items()):
        if i < 3:  # one favourite is no longer in the media folder
            (media / f"STK-{i}.webp").write_bytes(data)
    (media / "unrelated.webp").write_bytes(webp(99))
    found = android.match_media(backups, media)
    assert len(found) == 3 and all(android.file_hash(p) == d for d, p in found.items())


def test_favorites_prefer_decrypted_then_media(tmp_path: Path) -> None:
    key = crypt15.parse_key(KEY)
    backups, plain = make_backup_dir(tmp_path, key, range(2))
    plain_dir = tmp_path / "plain"
    android.decrypt_backups(backups, plain_dir, key)
    favorites = android.favorites(backups, plain_dir, tmp_path / "nowhere", tmp_path / "no-msgstore.db")
    assert {f.file_hash for f in favorites} == set(plain)
    assert all(f.size == len(plain[f.file_hash]) for f in favorites)


def make_sticker_db(path: Path) -> None:
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)
    conn.executemany("INSERT INTO Z_PRIMARYKEY (Z_ENT, Z_NAME, Z_SUPER, Z_MAX) VALUES (?,?,?,?)",
                     [(1, "WACDAbstractStickerPack", 0, 0), (4, "WACDSticker", 0, 0)])
    conn.execute("INSERT INTO ZWACDSTICKER (Z_PK, Z_ENT, Z_OPT, ZSTICKERPACK, ZFLAGS, ZFILEHASH, ZRELATIVEIMAGEPATH, "
                 "ZFILELENGTH, ZMIMETYPE) VALUES (7, 4, 1, NULL, 256, 'already', 'no-sticker-pack/x.webp', 10, 'image/webp')")
    conn.execute("UPDATE Z_PRIMARYKEY SET Z_MAX=7 WHERE Z_NAME='WACDSticker'")
    conn.commit()
    conn.close()


def test_import_favorites_into_iphone_db(tmp_path: Path) -> None:
    db = tmp_path / "Sticker.sqlite"
    make_sticker_db(db)
    files = []
    for seed in range(2):
        path = tmp_path / f"s{seed}.webp"
        path.write_bytes(webp(seed))
        files.append(path)
    favorites = [android.Favorite(b64hash(p.read_bytes()), p, p.stat().st_size, media_key=b"k" * 32,
                                  enc_hash="e", direct_path="/d", url="https://u") for p in files]
    favorites.append(android.Favorite("already", files[0], 10))  # on the iPhone already
    stored: list[tuple[str, Path]] = []
    added, skipped = ios.import_favorites(db, favorites, lambda rel, src: stored.append((rel, src)))
    assert (added, skipped) == (2, 1)
    assert all(rel.startswith("stickers/no-sticker-pack/") and rel.endswith(".webp") for rel, _ in stored)
    conn = sqlite3.connect(db)
    rows = conn.execute("SELECT Z_PK, Z_ENT, ZFLAGS, ZSTICKERPACK, ZFILEHASH, ZMIMETYPE, ZRELATIVEIMAGEPATH, ZMEDIAKEY "
                        "FROM ZWACDSTICKER WHERE ZFILEHASH<>'already' ORDER BY Z_PK").fetchall()
    assert [r[0] for r in rows] == [8, 9]
    assert all(r[1] == 4 and r[2] == 256 and r[3] is None and r[5] == "image/webp" for r in rows)
    assert all(r[6] == stored[i][0][len("stickers/"):] for i, r in enumerate(rows))
    assert conn.execute("SELECT Z_MAX FROM Z_PRIMARYKEY WHERE Z_NAME='WACDSticker'").fetchone()[0] == 9
    conn.close()


def test_import_rejects_unknown_layout(tmp_path: Path) -> None:
    db = tmp_path / "x.sqlite"
    sqlite3.connect(db).execute("CREATE TABLE nope (a)").connection.commit()
    import pytest
    with pytest.raises(ios.StickerError):
        ios.import_favorites(db, [], lambda rel, src: None)
