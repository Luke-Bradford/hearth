"""Step 4, part 6 (#88): the speed test - grading, one at a time with a gap, the schedule, the
test's own lag not counted as a slow spell, and the endpoint's guards."""
import http.client
import json
import sqlite3
import threading
import time
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

from hearth import analysis, collectors, episodes as ep, levels as lv, speedtest, store
from hearth.web import Handler
from tests.helpers import mem_db


class GradeTest(unittest.TestCase):
    def test_grades_by_the_worse_direction(self):
        self.assertEqual(lv.bufferbloat(15, 20, 30)["grade"], "A")            # +15
        self.assertEqual(lv.bufferbloat(15, 70, 30)["grade"], "B")            # +55
        self.assertEqual(lv.bufferbloat(15, 20, 150)["grade"], "C")           # +135
        g = lv.bufferbloat(15, 400, 20)
        self.assertEqual((g["grade"], g["level"], g["rise_ms"]), ("D", lv.BAD, 385))
        self.assertEqual(lv.bufferbloat(20, 15, 18)["rise_ms"], 0)            # faster when busy: no rise
        self.assertEqual(lv.bufferbloat(None, 20, 20)["level"], lv.UNKNOWN)   # nothing to compare


class OneAtATimeTest(unittest.TestCase):
    def setUp(self):
        speedtest._state.update(running=False, phase=None, started=None, ended=0.0, error=None, starts=[])
        p = mock.patch.object(speedtest, "_run", side_effect=lambda db: None)   # never touch the network here
        p.start()
        self.addCleanup(p.stop)
        self.addCleanup(speedtest._state.update, running=False, ended=0.0)

    def test_busy_while_running_and_for_a_minute_after(self):
        speedtest.start(lambda: None)
        with self.assertRaises(speedtest.Busy):
            speedtest.start(lambda: None)                                     # running
        speedtest._state.update(running=False, ended=time.time())
        with self.assertRaises(speedtest.Busy):
            speedtest.start(lambda: None)                                     # just ended
        speedtest._state.update(ended=time.time() - speedtest.MIN_GAP_S - 1)
        speedtest.start(lambda: None)                                         # a minute later: fine

    def test_at_most_four_an_hour(self):
        # security review: a minute apart alone let a LAN client fill the line a third of the time
        t = time.time()
        for i in range(speedtest.MAX_PER_HOUR):
            speedtest._state.update(running=False, ended=0.0)
            speedtest.start(lambda: None, now=t + i * 120)
        speedtest._state.update(running=False, ended=0.0)
        with self.assertRaisesRegex(speedtest.Busy, "at most 4 speed tests an hour"):
            speedtest.start(lambda: None, now=t + 600)
        speedtest._state.update(running=False, ended=0.0)
        speedtest.start(lambda: None, now=t + 3601)                          # an hour after the first

    def test_redirects_are_refused(self):
        # security review: the https check covers the configured URL; a redirect could go to http://
        # or to an address on your network - so none is followed
        import http.server
        import socketserver

        class Redirect(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", "http://192.168.1.1/admin")
                self.end_headers()

            def log_message(self, *a):
                pass
        srv = socketserver.TCPServer(("127.0.0.1", 0), Redirect)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        req = speedtest.urllib.request.Request(f"http://127.0.0.1:{srv.server_address[1]}/__down?bytes=1")
        with self.assertRaisesRegex(speedtest.urllib.error.HTTPError, "refused"):
            speedtest._opener.open(req, timeout=5)

    def test_only_https_servers(self):
        for bad in ("http://speed.example", "ftp://x", "speed.cloudflare.com", "https://"):
            with mock.patch.dict(speedtest.CFG, {"speedtest_server": bad}):
                with self.assertRaises(ValueError, msg=bad):
                    speedtest.server()
        with mock.patch.dict(speedtest.CFG, {"speedtest_server": "https://speed.cloudflare.com/"}):
            self.assertEqual(speedtest.server(), "https://speed.cloudflare.com")


class PhaseTest(unittest.TestCase):
    def test_setup_time_isnt_counted(self):
        def fake(deadline, count):
            while time.monotonic() < deadline:
                count(125_000)          # 1 Mb a step
                time.sleep(0.05)
        with mock.patch.object(speedtest, "PHASE_S", 1.0), mock.patch.object(speedtest, "WARMUP_S", 0.5):
            mbps = speedtest._phase(fake, 2)
        self.assertGreater(mbps, 20)      # ~2 streams x 20 Mb/s, counted over the half second after warm-up
        self.assertLess(mbps, 60)

    def test_nothing_after_the_phase_counts(self):
        # #99: a stream still reading after the phase ends (a stalled read) mustn't add to it
        def late(deadline, count):
            time.sleep(0.4)            # past the end of a 0.3 s phase
            count(10_000_000)
        with mock.patch.object(speedtest, "PHASE_S", 0.3), mock.patch.object(speedtest, "WARMUP_S", 0.0):
            self.assertEqual(speedtest._phase(late, 1), 0.0)

    def test_upload_bytes_are_counted_as_they_go_out(self):
        # #122: counted per piece as http.client sends it, not once the request finishes
        got = []
        body = speedtest._Counted(b"x" * 20_000, got.append)
        pieces = [body.read(8192), body.read(8192), body.read(8192), body.read(8192)]
        self.assertEqual([len(p) for p in pieces], [8192, 8192, 3616, 0])
        self.assertEqual(got, [8192, 8192, 3616])

    def test_upload_end_to_end_counts_while_the_request_is_still_open(self):
        seen, counted_before_reply = [], []

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers["Content-Length"])
                seen.append(len(self.rfile.read(n)))
                counted_before_reply.append(sum(counted))     # what the client had counted by now
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *a):
                pass
        srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        counted = []
        with mock.patch.object(speedtest, "UP_BYTES", 300_000), \
                mock.patch.object(speedtest, "_opener", urllib.request.build_opener()):
            run = speedtest._upload(f"http://127.0.0.1:{srv.server_address[1]}")
            run(time.monotonic() + 0.2, counted.append)           # a few requests (#124 review: room for at least one)
        self.assertTrue(seen)
        self.assertEqual(set(seen), {300_000})                   # each whole body, Content-Length right
        self.assertEqual(sum(counted), 300_000 * len(seen))
        # counted as sent: by the time the server has a body, the client has counted it - before the reply
        self.assertEqual(counted_before_reply, [300_000 * (i + 1) for i in range(len(seen))])

    def test_every_stream_failing_is_an_error(self):
        def broken(deadline, count):
            raise OSError("no route")
        with mock.patch.object(speedtest, "PHASE_S", 0.2), mock.patch.object(speedtest, "WARMUP_S", 0.0):
            with self.assertRaises(OSError):
                speedtest._phase(broken, 2)


class ScheduleTest(unittest.TestCase):
    AT = time.mktime((2026, 10, 20, 3, 0, 30, 0, 0, -1))

    def test_daily_at_the_time_once(self):
        self.assertTrue(collectors.speedtest_due("daily 03:00", self.AT, None))
        self.assertTrue(collectors.speedtest_due("daily 03:00", self.AT + 9 * 60, None))     # within ten minutes
        self.assertFalse(collectors.speedtest_due("daily 03:00", self.AT + 11 * 60, None))
        self.assertFalse(collectors.speedtest_due("daily 03:00", self.AT, "2026-10-20"))     # done today
        self.assertFalse(collectors.speedtest_due("daily 03:00", self.AT - 60, None))

    def test_anything_else_never(self):
        for s in ("off", "", None, "daily 3:00", "daily 24:00", "hourly", "daily 03:00 "):
            self.assertFalse(collectors.speedtest_due(s, self.AT, None), s)


class EpisodesTest(unittest.TestCase):
    def test_a_tests_own_lag_isnt_a_slow_spell(self):
        win = [(1000.0, 1025.0)]
        slow = {"start": 1005, "end": 1020, "kind": ep.KIND_SLOW, "context": []}
        loss = {"start": 1010, "end": 1015, "kind": ep.KIND_PROBLEM, "context": ["x"]}
        later = {"start": 2000, "end": 2010, "kind": ep.KIND_SLOW}
        out = analysis.during_speedtests([slow, loss, later], win)
        self.assertEqual([e["start"] for e in out], [1010, 2000])                # the slow spell inside is dropped
        self.assertIn("During a speed test", out[0]["context"][-1])               # a loss is kept, and labelled
        self.assertNotIn("context", out[1])
        self.assertEqual(analysis.during_speedtests([slow], []), [slow])

    def test_the_window_is_stored_before_the_test_runs(self):
        # #99: if Hearth stops mid-test the window must already be there, so its lag isn't counted
        c = mem_db()
        self.addCleanup(c.close)
        seen = []

        def fail_in_the_middle():
            seen.append(speedtest.windows(c, 0, 4e9))
            raise OSError("Hearth stopped")

        class Kept:
            def __getattr__(self, name):
                return getattr(c, name)

            def close(self):
                pass
        with mock.patch.object(speedtest, "server", side_effect=fail_in_the_middle):
            speedtest._run(lambda: Kept())
        [(start, end)] = seen[0]
        self.assertEqual(end - start, speedtest.LONGEST_S)                       # an upper bound, stored first
        self.assertEqual(c.execute("SELECT error FROM speedtests").fetchone()[0], "OSError: Hearth stopped")
        speedtest._state.update(running=False, ended=0.0)

    def test_a_database_that_wont_open_doesnt_leave_it_running(self):
        # #99: db() raising before the try left "running" on, so every later start was Busy
        speedtest._state.update(running=True, ended=0.0)

        def broken():
            raise OSError("disk gone")
        speedtest._run(broken)
        self.assertFalse(speedtest.state()["running"])
        speedtest._state.update(running=False, ended=0.0)

    def test_windows_come_from_stored_tests(self):
        c = mem_db()
        self.addCleanup(c.close)
        c.execute("INSERT INTO speedtests (ts, ended, down) VALUES (100, 125, 40)")
        self.assertEqual(speedtest.windows(c, 0, 200), [(100.0, 125.0)])
        self.assertEqual(speedtest.windows(c, 200, 300), [])


class EndpointTest(unittest.TestCase):
    def setUp(self):
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)
        self.c = sqlite3.connect(":memory:", check_same_thread=False)
        self.c.executescript(store.SCHEMA)
        self.addCleanup(self.c.close)
        c = self.c

        class Kept:
            def __getattr__(self, name):
                return getattr(c, name)

            def close(self):
                pass
        speedtest._state.update(running=False, ended=0.0, error=None, starts=[])
        self.addCleanup(speedtest._state.update, running=False, ended=0.0)
        for p in (mock.patch.object(store, "db", side_effect=lambda: Kept()),
                  mock.patch.object(speedtest, "_run", side_effect=lambda db: None)):
            p.start()
            self.addCleanup(p.stop)

    def post(self, origin=None):
        port = self.srv.server_address[1]
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        self.addCleanup(conn.close)   # closed even when an assertion fails (#71)
        conn.request("POST", "/api/speedtest", body=b"{}", headers={"Content-Type": "application/json",
                                                                   "Origin": origin or f"http://127.0.0.1:{port}"})
        r = conn.getresponse()
        out = (r.status, json.loads(r.read() or b"{}"))
        conn.close()
        return out

    def test_start_then_busy(self):
        self.assertEqual(self.post()[0], 202)
        status, body = self.post()
        self.assertEqual(status, 409)
        self.assertIn("already running", body["error"])

    def test_a_foreign_page_cant_start_one(self):
        self.assertEqual(self.post(origin="http://evil.example")[0], 403)
        self.assertFalse(speedtest.state()["running"])

    def test_the_view(self):
        self.c.execute("INSERT INTO speedtests (ts, ended, down, up, idle_ms, loaded_down_ms, loaded_up_ms, grade, server) "
                       "VALUES (1, 21, 43, 11, 16, 18, 17, 'A', 'speed.cloudflare.com')")
        v = speedtest.view(self.c)
        self.assertEqual((v["results"][0]["grade"], v["results"][0]["level"], v["running"]), ("A", lv.OK, False))
        self.assertEqual(v["server"], "speed.cloudflare.com")

    def test_a_bad_server_is_said_not_shown_as_null(self):
        # #99: the panel used an unchecked hostname ("Sends test data to null")
        with mock.patch.dict(speedtest.CFG, {"speedtest_server": "https://"}):
            v = speedtest.view(self.c)
        self.assertIsNone(v["server"])
        self.assertIn("https://", v["server_problem"])


if __name__ == "__main__":
    unittest.main()
