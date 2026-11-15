"""WhatsApp with several accounts keeps each extra account under accounts/<id>."""
import pytest

from wamove.android import adb

MAIN = "/sdcard/Android/media/com.whatsapp/WhatsApp"


def fake_shell(tree: dict[str, str]):
    adb.device = lambda: "Fake"  # the phone is present in these tests
    """Answer the few shell commands whatsapp_root uses from a path -> listing map."""
    def shell(command: str) -> str:
        if command.startswith("[ -d "):
            path = command.split('"')[1]
            return "yes\n" if any(k == path or k.startswith(path + "/") for k in tree) else ""
        if command.startswith("ls "):
            path = command.split('"')[1]
            return tree.get(path, "")
        if command.startswith("stat "):
            path = command.split('"')[1]
            return tree.get("stat:" + path, "0")
        raise AssertionError(command)
    return shell


def test_secondary_account_is_found(monkeypatch):
    monkeypatch.setattr(adb, "shell", fake_shell({
        f"{MAIN}/accounts": "1002\n",
        f"{MAIN}/accounts/1002/Databases": "msgstore.db.crypt15\n",
    }))
    assert adb.whatsapp_root() == f"{MAIN}/accounts/1002"


def test_newest_encrypted_backup_wins(monkeypatch):
    monkeypatch.setattr(adb, "shell", fake_shell({
        f"{MAIN}/Databases": "msgstore.db.crypt15\n",
        f"stat:{MAIN}/Databases/msgstore.db.crypt15": "100",
        f"{MAIN}/accounts": "1002\n",
        f"{MAIN}/accounts/1002/Databases": "msgstore.db.crypt15\n",
        f"stat:{MAIN}/accounts/1002/Databases/msgstore.db.crypt15": "200",
    }))
    assert adb.whatsapp_root() == f"{MAIN}/accounts/1002"


def test_older_format_in_secondary_account_is_reported(monkeypatch):
    monkeypatch.setattr(adb, "shell", fake_shell({
        f"{MAIN}/accounts": "1002\n",
        f"{MAIN}/accounts/1002/Databases": "msgstore.db.crypt14\n",
    }))
    with pytest.raises(adb.AdbError, match="older backup format"):
        adb.whatsapp_root()


def test_no_backup_anywhere(monkeypatch):
    monkeypatch.setattr(adb, "shell", fake_shell({f"{MAIN}/Media": ""}))
    with pytest.raises(adb.AdbError, match="no WhatsApp backup"):
        adb.whatsapp_root()


def test_unplugged_phone_is_not_a_missing_backup(monkeypatch):
    def no_phone():
        raise adb.AdbError("no Android phone found: turn on USB debugging, plug it in and allow this computer")
    monkeypatch.setattr(adb, "device", no_phone)
    with pytest.raises(adb.AdbError, match="no Android phone found"):
        adb.whatsapp_root()
