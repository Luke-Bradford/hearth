"""Daily backups of hearth.db (#129): its history is a year of readings, your names and your
settings in one file - a disk problem or a bad edit shouldn't lose it.

A backup is SQLite's own online copy, taken in steps so Hearth keeps writing meanwhile; it's
checked (PRAGMA quick_check) before it counts, then gzipped into the backup folder as
hearth-YYYY-MM-DD.db.gz. The newest `backup_keep` are kept. To restore: stop Hearth, unzip
one over hearth.db (and delete hearth.db-wal and -shm), start Hearth."""
import gzip
import os
import re
import shutil
import sqlite3
import time

from .config import CFG, DB_PATH, HERE

TIME_RE = re.compile(r"([01]\d|2[0-3]):([0-5]\d)")
NAME_RE = re.compile(r"hearth-(\d{4}-\d\d-\d\d)\.db\.gz")
CATCH_UP_S = 36 * 3600        # a backup older than this is made at once, not at the next backup_time
STEP_PAGES = 1024             # pages copied per step (4 MB): the database is never held for long
STEP_PAUSE_S = 0.005


class BackupError(Exception):
    """A backup that couldn't be made; the message says why (never a file's contents)."""


def keep():
    """How many to keep: backup_keep, 0 (off) to 365."""
    try:
        return max(0, min(365, int(CFG.get("backup_keep", 7))))
    except (TypeError, ValueError):
        return 7


def folder():
    d = CFG.get("backup_dir") or "backups"
    return d if os.path.isabs(d) else os.path.join(HERE, d)


def at():
    """(hour, minute) of the daily backup: backup_time "HH:MM", else 03:30."""
    m = TIME_RE.fullmatch(str(CFG.get("backup_time") or ""))
    return (int(m.group(1)), int(m.group(2))) if m else (3, 30)


def existing(dest):
    """[(day, path)] of the backups in `dest`, oldest first (only files Hearth names itself)."""
    try:
        names = os.listdir(dest)
    except OSError:
        return []
    return sorted((m.group(1), os.path.join(dest, n)) for n in names if (m := NAME_RE.fullmatch(n)))


def due(now, last, hour_minute):
    """Whether to make one now: none yet, the last is over CATCH_UP_S old, or it's past today's
    backup time and today's isn't made."""
    if last is None or now - last >= CATCH_UP_S:
        return True
    t = time.localtime(now)
    h, m = hour_minute
    past = (t.tm_hour, t.tm_min) >= (h, m)
    return past and time.strftime("%Y-%m-%d", time.localtime(last)) != time.strftime("%Y-%m-%d", t)


def make(dest=None, src=None, now=None, n_keep=None):
    """Make today's backup and prune the old ones. {"file", "bytes", "took_s", "kept"}, or
    BackupError. A day's backup made twice replaces the first."""
    dest, src, now = dest or folder(), src or DB_PATH, now if now is not None else time.time()
    n_keep = keep() if n_keep is None else n_keep
    start = time.monotonic()
    day = time.strftime("%Y-%m-%d", time.localtime(now))
    final = os.path.join(dest, f"hearth-{day}.db.gz")
    raw, packed = final[:-3] + ".tmp", final + ".tmp"
    try:
        os.makedirs(dest, exist_ok=True)
        s = sqlite3.connect(f"file:{src}?mode=ro", uri=True, timeout=30)
        try:
            d = sqlite3.connect(raw)
            try:
                s.backup(d, pages=STEP_PAGES, sleep=STEP_PAUSE_S)
                ok = d.execute("PRAGMA quick_check").fetchone()[0]
            finally:
                d.close()
        finally:
            s.close()
        if ok != "ok":
            raise BackupError("the copy didn't pass SQLite's check")
        with open(raw, "rb") as fin, gzip.open(packed, "wb", compresslevel=6) as fout:
            shutil.copyfileobj(fin, fout, 1 << 20)
        os.replace(packed, final)
    except (OSError, sqlite3.Error) as e:
        raise BackupError(f"couldn't make the backup ({type(e).__name__})") from None
    finally:
        for p in (raw, packed):
            try:
                os.remove(p)
            except OSError:
                pass
    try:
        size = os.path.getsize(final)
    except OSError as e:     # made, then gone at once (the folder cleaned meanwhile): a failure (#130 review)
        raise BackupError(f"the backup vanished once made ({type(e).__name__})") from None
    have = existing(dest)
    for _, path in have[:max(0, len(have) - n_keep)]:
        try:
            os.remove(path)
        except OSError:
            pass
    return {"file": os.path.basename(final), "bytes": size,
            "took_s": round(time.monotonic() - start, 1), "kept": min(len(have), n_keep)}
