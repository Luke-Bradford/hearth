import os
import shutil
import struct
import tempfile
import time
import unittest
from unittest import mock

from hearth import analysis, collectors, host, store
from hearth.config import IS_WIN
from tests.helpers import mem_db

GB = host.GB
MB = 1024 ** 2
H = 3600
T0 = 1_792_000_000


class LeakTest(unittest.TestCase):
    def test_steady_climb_is_a_leak(self):
        climb = {"com.docker.backend": [(i * H, int((2 + i) * GB)) for i in range(10)]}
        self.assertEqual([n for n, *_ in host.leaks(climb)], ["com.docker.backend"])

    def test_vm_memory_growth_is_not_a_leak(self):
        climb = {"vmmemWSL": [(i * H, int((2 + i) * GB)) for i in range(10)]}
        self.assertEqual(host.leaks(climb), [])

    def test_not_leaks(self):
        cases = {
            "short": [(i * 600, int((2 + i) * GB)) for i in range(10)],                 # under 6 hours
            "small": [(i * H, int(2 * GB + i * 50 * 1024 ** 2)) for i in range(10)],  # under 1 GB growth
            "sawtooth": [(i * H, int((2 + (i % 3) * 3) * GB)) for i in range(10)],    # rises and falls back
            "big_steady": [(i * H, int(40 * GB + i * 0.2 * GB)) for i in range(10)],  # +1.8 GB but only +4.5%
        }
        self.assertEqual(host.leaks(cases), [])


class WarningsTest(unittest.TestCase):
    BASE = {"cpu_pct": 5, "mem_total": 128 * GB, "mem_avail": 70 * GB, "commit": 60 * GB,
            "commit_limit": 136 * GB, "pool_paged": GB, "pool_nonpaged": int(0.5 * GB), "handles": 150_000,
            "uptime_s": 3 * 86400}

    def test_healthy(self):
        self.assertEqual(host.warnings(self.BASE), [])

    def test_handle_leak_named_and_explains_the_pool(self):
        s = {**self.BASE, "pool_nonpaged": int(3.5 * GB), "handles": 4_000_000, "uptime_s": 27 * 86400}
        procs = [("svchost (Remote Desktop Services)", int(0.3 * GB), 1, 3_800_000, 3_800_000)]
        out = host.warnings(s, (), procs)
        self.assertEqual(out[0][0], "bad")
        self.assertIn("svchost (Remote Desktop Services) holds 3,800,000", out[0][1])
        self.assertTrue(any("Likely the handle leak above" in t for _, t in out))
        self.assertEqual(out[-1], ("info", "Up for 27 days without a restart."))

    def test_many_healthy_processes_are_not_a_leak(self):
        # 40 Chrome processes, 6,000 handles each: 240,000 in total, none of them leaking
        out = host.warnings(self.BASE, (), [("chrome", 5 * GB, 40, 240_000, 6_000)])
        self.assertEqual(out, [])

    def test_one_leaking_process_among_many(self):
        out = host.warnings(self.BASE, (), [("svchost", GB, 30, 3_900_000, 3_800_000)])
        self.assertTrue(out[0][1].startswith("One svchost process holds 3,800,000"))

    def test_missing_values_dont_break_it(self):  # e.g. no uptime off Windows
        s = {**self.BASE, "uptime_s": None, "handles": None, "pool_nonpaged": None}
        self.assertEqual(host.warnings(s), [])

    def test_commit_near_the_limit(self):
        out = host.warnings({**self.BASE, "commit": 125 * GB})
        self.assertEqual(out[0][0], "bad")
        self.assertIn("92%", out[0][1])

    def test_leaking_program_reported(self):
        out = host.warnings(self.BASE, [("com.docker.backend", 2 * GB, 38 * GB)])
        self.assertIn("com.docker.backend has grown from 2.0 GB to 38.0 GB", out[0][1])


@unittest.skipUnless(IS_WIN, "reads the Windows API")
class ReaderTest(unittest.TestCase):
    def test_live_readings_are_sane(self):
        r = host.Reader()
        r.sample()
        time.sleep(0.2)
        s = r.sample()
        self.assertGreater(s["mem_avail"], 0)
        self.assertGreater(s["mem_total"], s["mem_avail"])
        self.assertGreater(s["commit_limit"], s["commit"])
        self.assertGreater(s["handles"], 0)
        self.assertTrue(0 <= s["cpu_pct"] <= 100)
        procs = r.processes()
        self.assertTrue(procs)
        for name, private, count, handles, most in procs:
            self.assertTrue(name)
            self.assertLessEqual(most, handles)
            self.assertGreaterEqual(count, 1)

    def test_service_names_right_after_boot(self):
        # time.monotonic() counts from boot on Windows: it is under the 10-minute cache
        # lifetime for the first 10 minutes, which must still read (not crash on a missing cache)
        from unittest import mock
        r = host.Reader()
        if not r.ok:
            self.skipTest("the reader is off on 32-bit Python")
        with mock.patch.object(host.time, "monotonic", return_value=5.0):
            first = r.service_names()
            self.assertIsInstance(first, dict)
            self.assertTrue(r.processes())
        with mock.patch.object(host.time, "monotonic", return_value=5.0 + host.Reader._SVC_TTL_S + 1):
            self.assertIsInstance(r.service_names(), dict)


class ServiceNameCacheTest(unittest.TestCase):
    """The caching rules around the service manager, with its answers scripted."""

    def names(self, reader, at):
        from unittest import mock
        with mock.patch.object(host.time, "monotonic", return_value=at):
            return reader.service_names()

    def reader(self, answers):
        from unittest import mock
        r = host.Reader()
        read = mock.Mock(side_effect=answers)
        r._read_services = read
        return r, read

    def test_good_answer_is_reused_then_refreshed(self):
        r, read = self.reader([{4: "A"}, {4: "B"}])
        self.assertEqual(self.names(r, 5.0), {4: "A"})
        self.assertEqual(self.names(r, 5.0 + host.Reader._SVC_TTL_S - 1), {4: "A"})  # cached
        self.assertEqual(self.names(r, 5.0 + host.Reader._SVC_TTL_S + 1), {4: "B"})  # refreshed
        self.assertEqual(read.call_count, 2)

    def test_failed_read_is_retried_at_most_once_a_minute(self):
        r, read = self.reader([{}, {}, {7: "C"}])
        self.assertEqual(self.names(r, 100.0), {})
        self.assertEqual(self.names(r, 130.0), {})            # within the retry gap: not asked
        self.assertEqual(read.call_count, 1)
        self.assertEqual(self.names(r, 100.0 + host.Reader._SVC_RETRY_S + 1), {})
        self.assertEqual(self.names(r, 100.0 + 2 * host.Reader._SVC_RETRY_S + 2), {7: "C"})

    def test_stale_names_are_dropped_after_failures(self):
        ttl, stale = host.Reader._SVC_TTL_S, host.Reader._SVC_STALE_S
        r, _ = self.reader([{4: "A"}, {}, {}])
        self.names(r, 0.0)
        self.assertEqual(self.names(r, ttl + 1), {4: "A"})     # failed, but recent enough to keep
        self.assertEqual(self.names(r, stale + 1), {})         # failed again, now too old


class HostViewTest(unittest.TestCase):
    def test_view_with_change_and_warnings(self):
        c = mem_db()
        self.addCleanup(c.close)
        now = time.time()
        c.execute("INSERT INTO host_stats VALUES (?,?,?,?,?,?,?,?,?,?)",
                  (now - 30, 7.0, 70 * GB, 128 * GB, 93 * GB, 136 * GB, 5 * GB, int(3.5 * GB), 4_000_000, 27 * 86400))
        c.executemany("INSERT INTO host_procs VALUES (?,?,?,?,?,?)", [
            (now - 3000, "com.docker.backend", 30 * GB, 2, 1900, 1800),
            (now - 60, "com.docker.backend", 38 * GB, 2, 1950, 1850),
            (now - 60, "svchost (Remote Desktop Services)", int(0.3 * GB), 1, 3_800_000, 3_800_000)])
        store.set_state(c, host.LEAKS_STATE_KEY, [["com.docker.backend", 2 * GB, 38 * GB]])
        v = analysis.host_view(c, 60)
        self.assertTrue(v["available"])
        self.assertEqual(v["processes"][0]["name"], "com.docker.backend")
        self.assertEqual(v["processes"][0]["change"], 8 * GB)
        self.assertEqual(v["current"]["uptime_s"], 27 * 86400)
        levels = [w["level"] for w in v["warnings"]]
        self.assertEqual(levels[0], "bad")
        self.assertTrue(any("com.docker.backend has grown" in w["text"] for w in v["warnings"]))

    def test_old_tables_gain_the_new_columns(self):
        import os
        import sqlite3
        import tempfile
        from unittest import mock
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.addCleanup(os.remove, path)
        old = sqlite3.connect(path)
        old.execute("CREATE TABLE host_stats (ts REAL NOT NULL, cpu REAL, mem_avail INTEGER, mem_total INTEGER, "
                    "commit_bytes INTEGER, commit_limit INTEGER, pool_paged INTEGER, pool_nonpaged INTEGER, handles INTEGER)")
        old.execute("CREATE TABLE host_procs (ts REAL NOT NULL, name TEXT NOT NULL, private INTEGER, count INTEGER, "
                    "handles INTEGER)")
        old.commit()
        old.close()
        with mock.patch.object(store, "DB_PATH", path):
            store.init_db()
        c = sqlite3.connect(path)
        self.addCleanup(c.close)
        self.assertIn("uptime_s", {r[1] for r in c.execute("PRAGMA table_info(host_stats)")})
        self.assertIn("max_handles", {r[1] for r in c.execute("PRAGMA table_info(host_procs)")})

    def test_off_without_recent_samples(self):
        c = mem_db()
        self.addCleanup(c.close)
        self.assertFalse(analysis.host_view(c, 60)["available"])
        store.prune(c, time.time())


class PoolTagTest(unittest.TestCase):
    """#127: the non-paged pool by driver."""

    @staticmethod
    def reply(entries, count=None):
        """A SystemPoolTagInformation reply: (tag bytes, non-paged allocs, frees, bytes) each."""
        raw = struct.pack("<I4x", len(entries) if count is None else count)
        for tag, na, nf, nu in entries:
            raw += struct.pack("<4sIIxxxxQIIQ", tag, 0, 0, 0, na, nf, nu)
        return raw

    def test_parse(self):
        raw = self.reply([(b"File", 10, 2, 50 * MB), (b"WrkU", 4_000_000, 10, 1100 * MB), (b"Idle", 0, 0, 0),
                          (b"\x01\x02ab", 5, 0, 9 * GB), (b"Cont", 9, 1, 100 * MB)])
        self.assertEqual(host.parse_pool_tags(raw, top=2), {"WrkU": (1100 * MB, 3_999_990), "Cont": (100 * MB, 8)})
        # a count past what was filled in, and a reply too short to read: no crash
        self.assertEqual(host.parse_pool_tags(self.reply([(b"File", 1, 0, MB)], count=999)), {"File": (MB, 1)})
        self.assertEqual(host.parse_pool_tags(b"\x01"), {})

    @unittest.skipUnless(IS_WIN, "Windows only")
    def test_live_read_needs_no_admin(self):
        tags = host.Reader().pool_tags()
        self.assertTrue(tags)
        self.assertTrue(all(len(t) == 4 and size > 0 for t, (size, _) in tags.items()))

    def test_owners_are_the_one_driver_with_the_tag(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        for name, body in (("acmeflt.sys", b"..WrkU..CDat.."), ("a.sys", b"..File.."), ("b.sys", b"File"),
                           ("notes.txt", b"Lone")):
            with open(os.path.join(d, name), "wb") as f:
                f.write(body)
        kernel = os.path.join(d, "kernel.exe")
        with open(kernel, "wb") as f:
            f.write(b"..SeTl..CDat..")
        with mock.patch.object(host, "file_version", return_value={"company": "Acme", "product": "Acme Shield",
                                                                   "description": "Shield filter driver"}):
            got = host.tag_owners(["WrkU", "CDat", "File", "SeTl", "Lone", "Gone"], folder=d, kernel=kernel)
        self.assertEqual(got["WrkU"], {"file": "acmeflt.sys", "company": "Acme", "product": "Acme Shield",
                                       "description": "Shield filter driver"})
        # also in the kernel; in two drivers; only in a non-driver file; nowhere: no owner
        self.assertEqual([got[t] for t in ("CDat", "File", "SeTl", "Lone", "Gone")], [None] * 5)

    def test_a_growing_driver_is_named_with_its_rate(self):
        c = mem_db()
        self.addCleanup(c.close)
        owner = {"file": "acmeflt.sys", "company": "Acme", "product": "Acme Shield",
                 "description": "Shield filter driver"}
        looked = []

        def owners_of(tags):
            looked.append(tags)
            return {t: owner if t == "WrkU" else None for t in tags}
        for i in range(8):   # eight hours: WrkU climbs 50 MB an hour, Cont holds steady
            collectors.record_pool_tags(c, T0 + i * H, {"WrkU": (500 * MB + i * 50 * MB, 0), "Cont": (100 * MB, 0)},
                                        3 * GB, owners_of)
        self.assertEqual(len(looked), 1)                                  # once, then kept for a day
        pool = analysis.host_pool(c, 3 * GB)
        self.assertEqual([t for t, *_ in pool["leaks"]], ["WrkU"])
        text = host.pool_cause(pool)
        self.assertEqual(text, "It's Acme Shield filter driver (acmeflt.sys): its memory (tag WrkU) has grown from "
                               "0.5 GB to 0.8 GB, about 1,200 MB a day, and never shrinks - a driver leak. Updating "
                               "Acme Shield (or reporting it to Acme) fixes it; restarting Windows clears it "
                               "for now.")
        warn = [t for lvl, t in host.warnings({"pool_nonpaged": 3 * GB}, pool=pool) if "non-paged" in t]
        self.assertIn("It's Acme Shield filter driver", warn[0])
        # a day later the owners are looked up again
        collectors.record_pool_tags(c, T0 + 26 * H, {"WrkU": (900 * MB, 0)}, 3 * GB, owners_of)
        self.assertEqual(len(looked), 2)

    def test_a_dominant_driver_is_named_before_it_is_seen_growing(self):
        owner = {"file": "x.sys", "company": "Acme", "product": "Acme Guard", "description": "Acme Guard driver"}
        pool = {"leaks": [], "top": [("Acme", 1 * GB)], "owners": {"Acme": owner}, "total": 3 * GB}
        self.assertEqual(host.pool_cause(pool), "The largest part, 1.0 GB, belongs to Acme Guard driver (x.sys) (tag Acme); "
                                                "if it keeps growing, that driver is leaking.")
        self.assertIsNone(host.pool_cause({**pool, "top": [("Acme", GB // 10)]}))      # a small share: not named
        self.assertIsNone(host.pool_cause({**pool, "owners": {}}))                  # no owner found: the old text
        self.assertIn("Often a driver leaking", host.warnings({"pool_nonpaged": 3 * GB}, pool=None)[0][1])

    def test_tags_trading_places_are_looked_up_once_each(self):
        # #128 review: within the day only never-seen tags are looked up, and kept with the rest
        c = mem_db()
        self.addCleanup(c.close)
        looked = []

        def owners_of(tags):
            looked.append(list(tags))
            return dict.fromkeys(tags)
        a = {"Aaaa": (900 * MB, 0), "Bbbb": (800 * MB, 0), "Cccc": (700 * MB, 0), "Dddd": (690 * MB, 0)}
        b = {**a, "Cccc": (680 * MB, 0)}                    # D and C swap third place
        for i, tags in enumerate((a, b, a, b, a)):
            collectors.record_pool_tags(c, T0 + i * H, tags, 3 * GB, owners_of)
        self.assertEqual(looked, [["Aaaa", "Bbbb", "Cccc"], ["Dddd"]])
        self.assertEqual(set(analysis.host_pool(c, 3 * GB)["owners"]), {"Aaaa", "Bbbb", "Cccc", "Dddd"})
        store.set_state(c, host.POOL_OWNERS_KEY, ["damaged"])                 # a wrong-kind row reads as none
        self.assertEqual(analysis.host_pool(c, 3 * GB)["owners"], {})

    def test_under_the_warning_line_no_driver_files_are_read(self):
        c = mem_db()
        self.addCleanup(c.close)
        owners_of = mock.Mock(return_value={})
        collectors.record_pool_tags(c, T0, {"WrkU": (100 * MB, 0)}, 1 * GB, owners_of)
        owners_of.assert_not_called()


if __name__ == "__main__":
    unittest.main()
