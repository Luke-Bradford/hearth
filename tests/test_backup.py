"""#129: daily backups of hearth.db (hearth/backup.py)."""
import gzip
import os
import shutil
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest import mock

from hearth import backup, collectors, sources
from tests.helpers import mem_db

DAY = 86400


def at(y, mo, d, h, mi):
    return time.mktime((y, mo, d, h, mi, 0, 0, 0, -1))


class DueTest(unittest.TestCase):
    def test_when(self):
        night = (3, 30)
        self.assertTrue(backup.due(at(2026, 10, 21, 1, 0), None, night))                        # none yet
        self.assertFalse(backup.due(at(2026, 10, 21, 3, 0), at(2026, 10, 20, 3, 31), night))   # before today's time
        self.assertTrue(backup.due(at(2026, 10, 21, 3, 31), at(2026, 10, 20, 3, 31), night))   # past it, none today
        self.assertFalse(backup.due(at(2026, 10, 21, 9, 0), at(2026, 10, 21, 3, 31), night))  # today's made
        self.assertTrue(backup.due(at(2026, 10, 21, 1, 0), at(2026, 10, 19, 12, 0), night))   # over 36 h: at once

    def test_settings(self):
        with mock.patch.dict(backup.CFG, {"backup_time": "25:00", "backup_keep": "x", "backup_dir": "b"}):
            self.assertEqual((backup.at(), backup.keep()), ((3, 30), 7))
            self.assertEqual(backup.folder(), os.path.join(backup.HERE, "b"))
        with mock.patch.dict(backup.CFG, {"backup_time": "01:05", "backup_keep": 999}):
            self.assertEqual((backup.at(), backup.keep()), ((1, 5), 365))


class MakeTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.src = os.path.join(self.dir, "hearth.db")
        c = sqlite3.connect(self.src)
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("CREATE TABLE t (x)")
        c.executemany("INSERT INTO t VALUES (?)", [(i,) for i in range(5000)])
        c.commit()
        self.addCleanup(c.close)    # kept open: a backup is taken while Hearth has the database open
        self.dest = os.path.join(self.dir, "backups")

    def restored_rows(self, name):
        out = os.path.join(self.dir, "restored.db")
        with gzip.open(os.path.join(self.dest, name), "rb") as f, open(out, "wb") as g:
            shutil.copyfileobj(f, g)
        r = sqlite3.connect(out)
        try:
            return r.execute("SELECT COUNT(*) FROM t").fetchone()[0]
        finally:
            r.close()

    def test_a_backup_restores_and_old_ones_are_pruned(self):
        res = backup.make(self.dest, self.src, at(2026, 10, 21, 3, 30), 3)
        self.assertEqual((res["file"], res["kept"]), ("hearth-2026-10-21.db.gz", 1))
        self.assertEqual(self.restored_rows(res["file"]), 5000)
        for day in range(22, 27):
            backup.make(self.dest, self.src, at(2026, 10, day, 3, 30), 3)
        with open(os.path.join(self.dest, "notes.txt"), "w") as f:
            f.write("mine")                                                  # not Hearth's: never touched
        backup.make(self.dest, self.src, at(2026, 10, 27, 3, 30), 3)
        self.assertEqual(sorted(os.listdir(self.dest)), ["hearth-2026-10-25.db.gz", "hearth-2026-10-26.db.gz",
                                                         "hearth-2026-10-27.db.gz", "notes.txt"])
        self.assertFalse([n for n in os.listdir(self.dest) if n.endswith(".tmp")])

    def test_a_failure_says_why_and_leaves_nothing_half_made(self):
        with self.assertRaises(backup.BackupError) as e:
            backup.make(self.dest, os.path.join(self.dir, "missing.db"), at(2026, 10, 21, 3, 30), 3)
        self.assertIn("couldn't make the backup", str(e.exception))
        self.assertEqual(os.listdir(self.dest), [])


class LoopTest(unittest.TestCase):
    def test_off_when_none_are_kept(self):
        db, stop = mem_db(), threading.Event()
        self.addCleanup(db.close)
        stop.set()
        with mock.patch.dict(backup.CFG, {"backup_keep": 0}), \
                mock.patch.object(collectors, "_report_unconfigured") as off:
            collectors.backup_loop(stop)
        off.assert_called_once_with(sources.BACKUP, "turned off in config.json (backup_keep: 0)")

    def test_made_when_due_and_reported(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        db, stop = mem_db(), threading.Event()
        self.addCleanup(db.close)
        waits = []

        def wait(t=None):
            waits.append(t)
            if len(waits) > 1:      # the first wait is the start-up delay; stop after one round
                stop.set()
            return stop.is_set()

        class Kept:      # the loop's connection, left open for the test to read
            def __getattr__(self, name):
                return getattr(db, name)

            def close(self):
                pass
        with mock.patch.dict(backup.CFG, {"backup_keep": 7, "backup_dir": d}), \
                mock.patch.object(collectors.store, "db", return_value=Kept()), \
                mock.patch.object(backup, "make", return_value={"file": "hearth-2026-10-21.db.gz", "bytes": 5, "took_s": 0.1,
                                                                "kept": 1}) as made, \
                mock.patch.object(stop, "wait", side_effect=wait), mock.patch.object(collectors, "log"):
            collectors.backup_loop(stop)
        made.assert_called_once()
        st = sources.read(db, sources.BACKUP)
        self.assertEqual((st["ok"], st["detail"]["file"]), (True, "hearth-2026-10-21.db.gz"))


class RoundTest(unittest.TestCase):
    """#130 review: one look of the loop, and what it does when things go wrong."""

    def setUp(self):
        self.db = mem_db()
        self.addCleanup(self.db.close)
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        p = mock.patch.dict(backup.CFG, {"backup_keep": 7, "backup_dir": self.dir})
        p.start()
        self.addCleanup(p.stop)
        q = mock.patch.object(collectors, "log")
        q.start()
        self.addCleanup(q.stop)

    def test_a_failure_waits_an_hour_before_trying_again(self):
        with mock.patch.object(backup, "make", side_effect=backup.BackupError("couldn't make the backup (OSError)")) as made:
            failed = collectors._backup_round(self.db, T, None)
            self.assertEqual(failed, T)
            self.assertFalse(sources.read(self.db, sources.BACKUP)["ok"])
            collectors._backup_round(self.db, T + 600, failed)                    # ten minutes on: not again
            self.assertEqual(made.call_count, 1)
            collectors._backup_round(self.db, T + collectors.BACKUP_RETRY_S, failed)
            self.assertEqual(made.call_count, 2)

    def test_a_backup_gone_between_listing_and_reading_is_no_crash(self):
        with open(os.path.join(self.dir, "hearth-2026-10-20.db.gz"), "wb") as f:
            f.write(b"x")
        with mock.patch.object(collectors.os.path, "getmtime", side_effect=FileNotFoundError), \
                mock.patch.object(backup, "make", return_value={"file": "f", "bytes": 1, "took_s": 0, "kept": 1}) as made:
            self.assertIsNone(collectors._backup_round(self.db, T, None))         # treated as none: one is made
        made.assert_called_once()

    def test_a_backup_that_vanishes_once_made_is_a_failure(self):
        src = os.path.join(self.dir, "src.db")
        sqlite3.connect(src).close()
        with mock.patch.object(backup.os.path, "getsize", side_effect=FileNotFoundError):
            with self.assertRaises(backup.BackupError):
                backup.make(os.path.join(self.dir, "out"), src, T, 3)


T = at(2026, 10, 21, 4, 0)


if __name__ == "__main__":
    unittest.main()
