"""Programmatic interface for graphical front ends.

Each function does the same work as the matching ``wamove`` CLI command, but reports through a
callback instead of printing, and never asks for input. The CLI is untouched; this module only
re-arranges calls to the existing engine.

A ``report`` callback receives ``Event`` objects. Long steps send ``progress`` events; the iPhone
backup and restore also send ``need`` / ``clear`` when the iPhone shows its passcode prompt.
Errors are raised as the engine's own exceptions so callers can map them however they like.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import shutil
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from .android import adb, crypt15
from .cli import CHATSTORAGE, Failure, Work, load_archive
from .ios import backup as ios_backup
from .ios import chatstorage, device

Report = Callable[["Event"], None]
BACKUP_LOGGER = "pymobiledevice3.services.mobilebackup2"


@dataclass
class Event:
    step: str
    kind: str  # progress | need | clear | log
    pct: float | None = None
    phase: str | None = None
    data: dict = field(default_factory=dict)


class Cancelled(Exception):
    pass


class NotEnoughSpace(Exception):
    def __init__(self, needed: int, free: int):
        super().__init__(f"needs {needed} bytes, {free} free")
        self.needed, self.free = needed, free


class FindMyOn(Exception):
    pass


class PasswordNeeded(Exception):
    pass


class WhatsAppMissing(Exception):
    pass


class NothingToRestore(Exception):
    pass


def _noop(_: Event) -> None:
    pass


# ----- status -------------------------------------------------------------------------------------

def android_status() -> dict:
    """What adb sees, without changing anything on the phone."""
    try:
        rows = [line.split() for line in adb.run("devices", "-l").splitlines()[1:] if line.strip()]
    except (adb.AdbError, OSError) as e:
        return {"state": "no_adb", "detail": str(e)}
    if not rows:
        return {"state": "missing"}
    ready = [row for row in rows if len(row) > 1 and row[1] == "device"]
    if not ready:
        status = rows[0][1] if len(rows[0]) > 1 else "unknown"
        return {"state": "unauthorized" if status == "unauthorized" else "offline", "status": status}
    if len(ready) > 1:
        return {"state": "several"}
    model = next((p.split(":", 1)[1] for p in ready[0] if p.startswith("model:")), ready[0][0])
    result = {"state": "ready", "model": model.replace("_", " ")}
    try:
        root = adb.whatsapp_root()
    except adb.AdbError as e:
        result["backup"] = "old_format" if "older backup format" in str(e) else "none"
        return result
    stamp = adb.shell(f'stat -c %Y "{root}/Databases/msgstore.db.crypt15" 2>/dev/null').strip()
    now = adb.shell("date +%s").strip()
    result["backup"] = "ok"
    result["backup_time"] = int(stamp) if stamp.isdigit() else None
    result["backup_age_s"] = (int(now) - int(stamp)) if stamp.isdigit() and now.isdigit() else None
    return result


def iphone_status(udid: str | None = None, with_apps: bool = False) -> dict:
    try:
        phone = device.phone(udid)
    except device.DeviceError as e:
        return {"state": "untrusted" if "trust" in str(e) else "missing"}
    except Exception as e:  # usbmuxd hiccups while the phone reboots
        return {"state": "missing", "detail": type(e).__name__}
    result = {
        "state": "ready", "udid": phone.udid, "name": phone.name, "ios": phone.ios,
        "used_bytes": phone.used_bytes, "find_my": phone.find_my, "encrypted": phone.encrypts_backups,
    }
    if with_apps:
        result["whatsapp"] = whatsapp_installed(phone.udid)
    return result


def whatsapp_installed(udid: str | None = None) -> bool | None:
    async def go():
        from pymobiledevice3.services.installation_proxy import InstallationProxyService
        lockdown = await device._lockdown(udid)
        try:
            service = InstallationProxyService(lockdown=lockdown)
            try:
                apps = await service.get_apps(application_type="User",
                                              bundle_identifiers=["net.whatsapp.WhatsApp"])
            finally:
                close = getattr(service, "close", None)
                if close:
                    result = close()
                    if asyncio.iscoroutine(result):
                        await result
            return "net.whatsapp.WhatsApp" in apps
        finally:
            await lockdown.close()
    try:
        return asyncio.run(go())
    except Exception:
        return None


# ----- Android ------------------------------------------------------------------------------------

def key_sample(work: Work) -> Path:
    """Copy the smallest encrypted file from the phone so a typed key can be checked quickly."""
    root = adb.whatsapp_root()
    listing = adb.shell(f'stat -c "%s %n" "{root}"/Backups/*.crypt15 "{root}"/Databases/*.crypt15 2>/dev/null')
    files = []
    for line in listing.splitlines():
        size, _, name = line.strip().partition(" ")
        if size.isdigit() and name.endswith(".crypt15"):
            files.append((int(size), name))
    remote = min(files)[1] if files else f"{root}/Databases/msgstore.db.crypt15"
    target = work.root / "sample"
    shutil.rmtree(target, ignore_errors=True)
    target.mkdir(mode=0o700, parents=True)
    adb.pull(remote, target)
    found = sorted(target.glob("*.crypt15"))
    if not found:
        raise adb.AdbError("could not copy a backup file to check the key")
    return found[0]


def key_opens(sample: Path, key: bytes) -> bool:
    """True when the AES-GCM tag of any .crypt15 file checks out under this key.

    Only the right key passes the tag check, so a tiny settings file is enough: the content does not
    have to be a database the way `crypt15.decrypt` requires.
    """
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    data = sample.read_bytes()
    try:
        offset, ivs = crypt15._header(data)
    except crypt15.Crypt15Error:
        return False
    body = data[offset:]
    gcm = AESGCM(crypt15.derive_aes_key(key))
    for iv in ivs:
        for trailer in (0, 16):
            try:
                gcm.decrypt(iv, body[:len(body) - trailer], None)
                return True
            except InvalidTag:
                continue
    return False


def _folder_bytes(path: Path) -> int:
    total = 0
    for directory, _, files in os.walk(path):
        for name in files:
            try:
                total += os.lstat(os.path.join(directory, name)).st_size
            except OSError:
                continue
    return total


def _pull_watched(remote: str, local: Path, watch: Path, on_bytes: Callable[[int], None],
                  cancel: threading.Event) -> None:
    local.mkdir(parents=True, exist_ok=True)
    process = subprocess.Popen([adb._adb(), "pull", "-a", remote, str(local)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        while True:
            try:
                process.wait(timeout=1.0)
                break
            except subprocess.TimeoutExpired:
                pass
            if cancel.is_set():
                process.terminate()
                process.wait()
                raise Cancelled()
            on_bytes(_folder_bytes(watch))
        if process.returncode:
            error = (process.stderr.read() or b"").decode(errors="replace").strip()
            raise adb.AdbError(f"adb pull {remote} failed: {error}")
        on_bytes(_folder_bytes(watch))
    finally:
        if process.poll() is None:
            process.kill()


def _remote_file_bytes(path: str) -> int:
    size = adb.shell(f'stat -c %s "{path}" 2>/dev/null').strip()
    return int(size) if size.isdigit() else 0


def _remote_file_bytes(path: str) -> int:
    size = adb.shell(f'stat -c %s "{path}" 2>/dev/null').strip()
    return int(size) if size.isdigit() else 0


def pull(work: Work, report: Report = _noop, cancel: threading.Event | None = None) -> dict:
    """``wamove pull`` with byte progress over the database and every media folder.

    An interrupted copy is started over; only a copy that was already decrypted is kept, so a
    front end can simply retry.
    """
    cancel = cancel or threading.Event()
    root = adb.whatsapp_root()
    if work.msgstore.exists():
        raise Failure("this workspace already contains Android data; choose a new --work folder to preserve it")
    shutil.rmtree(work.android, ignore_errors=True)
    work.android.mkdir(mode=0o700, parents=True, exist_ok=True)
    database = f"{root}/Databases/msgstore.db.crypt15"
    db_bytes = _remote_file_bytes(database)
    folders = adb.media_dirs(root)
    sizes = {folder: adb.remote_bytes(f"{root}/Media/{folder}") for folder in folders}
    needed = db_bytes + sum(sizes.values())
    free = shutil.disk_usage(work.root).free
    if needed > free:
        raise NotEnoughSpace(needed, free)

    def progress(done: int, phase: str) -> None:
        report(Event("copy", "progress", pct=100 * done / needed if needed else 100, phase=phase,
                     data={"done_bytes": done, "total_bytes": needed}))

    progress(0, "chats")
    _pull_watched(database, work.crypt15.parent, work.crypt15.parent,
                  lambda landed: progress(min(landed, db_bytes), "chats"), cancel)
    finished = db_bytes
    names = adb.contacts()
    work.contacts.write_text(json.dumps(names, ensure_ascii=False, indent=1), encoding="utf-8")
    for folder in folders:
        if cancel.is_set():
            raise Cancelled()
        _pull_watched(f"{root}/Media/{folder}", work.media, work.media / folder,
                      lambda landed, folder=folder: progress(finished + min(landed, sizes[folder]), folder), cancel)
        finished += sizes[folder]
    progress(needed, "media")
    return {"contacts": len(names), "media_bytes": needed - db_bytes, "folders": sizes}


def decrypt(work: Work, key: bytes, report: Report = _noop) -> dict:
    """``wamove decrypt`` with the key given directly. Returns the archive summary."""
    if not work.crypt15.is_file():
        raise Failure("there is no Android backup yet; run `wamove pull` first")
    report(Event("copy", "progress", pct=None, phase="decrypt"))
    crypt15.decrypt_file(work.crypt15, work.msgstore, key)
    os.chmod(work.msgstore, 0o600)
    report(Event("copy", "progress", pct=0, phase="read"))
    return summary(work, report=report)


def _reader_progress(step: str, report: Report):
    def on_progress(done: int, total: int) -> None:
        report(Event(step, "progress", pct=100 * done / total if total else None, phase="read",
                     data={"done": done, "total": total}))
    return on_progress


def summary(work: Work, exclude_groups: bool = False, report: Report = _noop, step: str = "copy") -> dict:
    archive = load_archive(work, None, exclude_groups=exclude_groups, on_progress=_reader_progress(step, report))
    stats = archive.stats()
    stamps = [m.timestamp_ms for c in archive.chats for m in c.messages if m.timestamp_ms]
    stats.update({
        "first_ms": min(stamps) if stamps else None,
        "last_ms": max(stamps) if stamps else None,
        "sent": sum(1 for c in archive.chats for m in c.messages if m.from_me),
        "skipped": archive.skipped,
        "downgraded_types": archive.downgraded_types,
        "unconverted_tables": archive.unconverted_tables,
        "source_messages": archive.source_messages,
    })
    return stats


# ----- iPhone -------------------------------------------------------------------------------------

class _PasscodeHandler(logging.Handler):
    """pymobiledevice3 logs when the iPhone shows its passcode prompt; turn that into events."""

    def __init__(self, step: str, report: Report):
        super().__init__(logging.INFO)
        self.step, self.report = step, report

    def emit(self, record: logging.LogRecord) -> None:
        try:
            text = record.getMessage()
        except Exception:
            return
        if "enter the device passcode" in text:
            self.report(Event(self.step, "need", data={"what": "passcode"}))
        elif "passcode prompt dismissed" in text:
            self.report(Event(self.step, "clear", data={"what": "passcode"}))


def _with_passcode_events(step: str, report: Report, run: Callable[[], None]) -> None:
    handler = _PasscodeHandler(step, report)
    logger = logging.getLogger(BACKUP_LOGGER)
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    try:
        run()
    finally:
        logger.removeHandler(handler)


def check_password(path: Path, password: str | None) -> None:
    """Fail before any phone work when an encrypted backup's password is missing or wrong."""
    if not ios_backup.is_encrypted(path):
        return
    if not password:
        raise PasswordNeeded()
    ios_backup.Backup(path, password).close()


def backup_age(work: Work, udid: str) -> float | None:
    """Seconds since a full backup of this iPhone was taken into this work folder, or None."""
    manifest = work.full / udid / "Manifest.db"
    if not manifest.is_file():
        return None
    return max(0.0, time.time() - manifest.stat().st_mtime)


def backup(work: Work, report: Report = _noop, password: str | None = None, udid: str | None = None,
           reuse: bool = False) -> dict:
    """``wamove backup``: full iPhone backup, then a WhatsApp-only copy.

    With ``reuse`` an earlier full backup of the same iPhone is kept and only the WhatsApp copy is
    remade, which saves the slow part when a transfer is attempted again.
    """
    phone = device.phone(udid)
    work.root.mkdir(mode=0o700, parents=True, exist_ok=True)
    for stale in (work.pristine, work.patched):
        shutil.rmtree(stale, ignore_errors=True)
    if reuse and backup_age(work, phone.udid) is not None:
        report(Event("backup", "progress", pct=100, phase="phone"))
        return _keep_whatsapp(work, report, phone, password)
    shutil.rmtree(work.full, ignore_errors=True)
    free = shutil.disk_usage(work.root).free
    if phone.used_bytes and phone.used_bytes > free:
        raise NotEnoughSpace(phone.used_bytes, free)
    if phone.encrypts_backups and not password:
        raise PasswordNeeded()

    def progress(percent: float) -> None:
        report(Event("backup", "progress", pct=percent, phase="phone"))

    async def go() -> None:
        lockdown = await device._lockdown(phone.udid)
        try:
            service = await device._service(lockdown)
            try:
                await service.backup(full=True, backup_directory=work.full, progress_callback=progress)
            finally:
                await service.close()
        finally:
            await lockdown.close()

    work.full.mkdir(parents=True, exist_ok=True)
    report(Event("backup", "progress", pct=0, phase="phone"))
    _with_passcode_events("backup", report, lambda: asyncio.run(go()))
    return _keep_whatsapp(work, report, phone, password)


def _keep_whatsapp(work: Work, report: Report, phone: device.Phone, password: str | None) -> dict:
    full = work.full / phone.udid
    check_password(full, password)
    report(Event("backup", "progress", pct=None, phase="copy"))
    ios_backup.clone_tree(full, work.pristine / phone.udid)
    with ios_backup.Backup(work.pristine / phone.udid, password) as saved:
        saved.prune()
        if not saved.get(CHATSTORAGE):
            raise WhatsAppMissing()
        count = saved.count()
    report(Event("backup", "progress", pct=100, phase="copy"))
    return {"udid": phone.udid, "entries": count, "used_bytes": phone.used_bytes,
            "encrypted": ios_backup.is_encrypted(full), "reused": backup_age(work, phone.udid)}


class _CountingWriter(chatstorage.Writer):
    def __init__(self, path: Path, lids: dict[str, str] | None, on_messages: Callable[[int], None]):
        super().__init__(path, lids)
        self.on_messages = on_messages

    def _import_chat(self, chat, archive, report, media_root):
        session = super()._import_chat(chat, archive, report, media_root)
        self.on_messages(len(chat.messages))
        return session


def build(work: Work, report: Report = _noop, cancel: threading.Event | None = None,
          password: str | None = None, exclude_groups: bool = False) -> dict:
    """``wamove build`` with progress, writing the same ``report.json`` the CLI's restore checks."""
    cancel = cancel or threading.Event()
    udid = work.udid()
    pristine = work.pristine / udid
    check_password(pristine, password)
    report(Event("prepare", "progress", pct=0, phase="read"))
    archive = load_archive(work, None, exclude_groups=exclude_groups,
                           on_progress=lambda done, total: report(Event("prepare", "progress",
                                                                        pct=10 * done / total if total else 0,
                                                                        phase="read")))
    stats = archive.stats()
    if work.build.exists() or (work.patched / udid).exists():
        raise Failure("build output already exists; preserve it and use a separate workspace for another attempt")
    work.build.mkdir(parents=True)
    result = {"completed": False, "udid": udid, "source_messages": archive.source_messages,
              "selected": stats, "skipped": archive.skipped,
              "downgraded_types": archive.downgraded_types, "unconverted_tables": archive.unconverted_tables,
              "device_validated": False, "group_mapping_experimental": bool(stats["groups"])}
    work.report.write_text(json.dumps(result, indent=2), encoding="utf-8")
    ios_backup.clone_tree(pristine, work.patched / udid)
    media = work.media if work.media.is_dir() else None
    media_bytes = sum(f.stat().st_size for f in media.rglob("*") if f.is_file()) if media else 0
    needed = media_bytes + 2 * 1024 ** 3
    free = shutil.disk_usage(work.root).free
    if needed > free:
        raise NotEnoughSpace(needed, free)
    database = work.build / CHATSTORAGE
    total_messages = max(stats["messages"], 1)
    imported = [0]

    def on_messages(count: int) -> None:
        if cancel.is_set():
            raise Cancelled()
        imported[0] += count
        report(Event("prepare", "progress", pct=70 * imported[0] / total_messages, phase="chats",
                     data={"done": imported[0], "total": stats["messages"]}))

    with ios_backup.Backup(work.patched / udid, password) as target:
        for name in (CHATSTORAGE, CHATSTORAGE + "-wal"):
            target.read(name, work.build / name)
        writer = _CountingWriter(database, archive.lids, on_messages)
        (work.build / "thumbs").mkdir()
        try:
            written = writer.import_archive(archive, media, work.build / "thumbs")
        finally:
            writer.close()
        problems = chatstorage.verify(database)
        if problems:
            raise Failure("the converted database failed its checks:\n  " + "\n  ".join(problems))
        target.put(CHATSTORAGE, database)
        empty = work.build / "empty"
        empty.write_bytes(b"")
        for suffix in ("-wal", "-shm"):
            target.put(CHATSTORAGE + suffix, empty)
        total = len(written.media_files)
        for done, item in enumerate(written.media_files, 1):
            if cancel.is_set():
                raise Cancelled()
            target.put(item.relative_path, Path(item.source))
            if done % 50 == 0 or done == total:
                report(Event("prepare", "progress", pct=70 + 25 * done / max(total, 1), phase="media",
                             data={"done": done, "total": total}))
        report(Event("prepare", "progress", pct=95, phase="check"))
        problems = target.check()
        if problems:
            raise Failure("the modified backup failed its checks:\n  " + "\n  ".join(problems[:20]))
    result.update({"completed": True, "messages_written": written.messages_written,
                   "duplicates_skipped": written.messages_skipped, "media_linked": written.media_linked,
                   "media_missing": written.media_missing, "thumbnails": written.thumbnails,
                   "manifest_sha256": hashlib.sha256((work.patched / udid / "Manifest.db").read_bytes()).hexdigest()})
    work.report.write_text(json.dumps(result, indent=2), encoding="utf-8")
    report(Event("prepare", "progress", pct=100, phase="check"))
    return {
        "chats_created": written.sessions_created,
        "chats_merged": written.sessions_reused,
        "messages_added": written.messages_written,
        "messages_skipped": written.messages_skipped,
        "media_found": written.media_linked,
        "media_missing": written.media_missing,
        "thumbnails": written.thumbnails,
        "coverage": result,
    }


def restore(work: Work, report: Report = _noop, source: str = "patched", password: str | None = None) -> dict:
    """``wamove restore`` (source="patched") or ``wamove rollback`` (source="pristine")."""
    step = "restore" if source == "patched" else "undo"
    root = work.patched if source == "patched" else work.pristine
    try:
        udid = work.udid()
    except Failure as e:
        raise NothingToRestore() from e
    if not (root / udid / "Manifest.db").is_file():
        raise NothingToRestore()
    if source == "patched":
        if not work.report.is_file():
            raise Failure("this build has no validation report; refusing to restore")
        result = json.loads(work.report.read_text(encoding="utf-8"))
        digest = hashlib.sha256((root / udid / "Manifest.db").read_bytes()).hexdigest()
        if not result.get("completed") or result.get("udid") != udid or result.get("manifest_sha256") != digest:
            raise Failure("this build is incomplete or its manifest changed; refusing to restore")
    check_password(root / udid, password)
    phone = device.phone(udid)
    if phone.udid != udid:
        raise Failure("the connected iPhone does not match the backup; refusing to restore")
    if phone.find_my:
        raise FindMyOn()

    def progress(percent: float) -> None:
        report(Event(step, "progress", pct=percent, phase="phone"))

    report(Event(step, "progress", pct=0, phase="phone"))
    _with_passcode_events(step, report, lambda: _run_restore(root, udid, password, progress))
    report(Event(step, "progress", pct=100, phase="phone"))
    return {"used_bytes_before": phone.used_bytes}


def _run_restore(root: Path, udid: str, password: str | None, progress: Callable[[float], None]) -> None:
    async def go() -> None:
        lockdown = await device._lockdown(udid)
        try:
            service = await device._service(lockdown)
            try:
                await service.restore(backup_directory=root, system=True, reboot=True, copy=False, settings=True,
                                      remove=False, password=password or "", source=udid,
                                      progress_callback=progress, skip_apps=True)
            finally:
                await service.close()
        finally:
            await lockdown.close()

    asyncio.run(go())
