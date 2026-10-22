"""Step 6, part 1 (#117): Hearth sends its own notifications (hearth/notify.py)."""
import json
import os
import socket
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

from hearth import levels as lv, notify, settings, sources, store
from tests.helpers import mem_db

NOW = 1_800_000_000


def creds(test, text):
    fd, path = tempfile.mkstemp()
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    test.addCleanup(os.remove, path)
    return path


def alert(c, level, text, first, kind="state", cleared=None):
    c.execute("INSERT INTO alerts (key, level, text, first, last, cleared, kind) VALUES (?,?,?,?,?,?,?)",
              (f"k|{text}", level, text, first, first, cleared, kind))


class Receiver:
    """A local webhook: records each POST; answers with `status` (or a redirect)."""

    def __init__(self, test, status=204, redirect=None):
        self.posts, self.status, self.redirect = [], status, redirect
        rec = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                rec.posts.append((self.path, dict(self.headers), json.loads(body)))
                if rec.redirect:
                    self.send_response(302)
                    self.send_header("Location", rec.redirect)
                else:
                    self.send_response(rec.status)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *a):
                pass
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        test.addCleanup(self.srv.server_close)
        test.addCleanup(self.srv.shutdown)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}/hook/secret-token"


class UrlTest(unittest.TestCase):
    def test_what_counts_as_a_channel_address(self):
        for ok in ("https://ntfy.sh/my-topic", "http://192.168.1.5:8090/hook", "https://ntfy.example.com/alerts",
                   "https://discord.com/api/webhooks/1/abc", "https://hooks.slack.com/services/T/B/x"):
            self.assertEqual(notify.check_url(ok), ok)
        for bad in ("", "ftp://x/y", "http://host:abc/x", "http://host:99999/x", "https://", "ntfy.sh/topic", "https://ntfy.sh/", "https://a b/c",
                    "https://x/\n", "https://x/" + "a" * 600, None, 5, "javascript:alert(1)"):
            with self.assertRaises(notify.Invalid, msg=repr(bad)):
                notify.check_url(bad)

    def test_the_kind_comes_from_the_address(self):
        self.assertEqual([notify.kind_of(u) for u in (
            "https://ntfy.sh/t", "https://NTFY.home.lan/t", "https://discord.com/api/webhooks/1/x",
            "https://discord.com/channels/1", "https://hooks.slack.com/services/x", "http://10.0.0.2/hook")],
            [notify.NTFY, notify.NTFY, notify.DISCORD, notify.WEBHOOK, notify.SLACK, notify.WEBHOOK])

    def test_channels_and_the_token_from_the_file(self):
        path = creds(self, "GLINET_PASSWORD=x\nNOTIFY_URL=https://ntfy.sh/abc\nNOTIFY_URL_2=not a url\nNOTIFY_TOKEN=tk_AgQd7\n")
        chans, token = notify.channels(path)
        self.assertEqual(chans, [("NOTIFY_URL", "https://ntfy.sh/abc", notify.NTFY), ("NOTIFY_URL_2", "not a url", None)])
        self.assertEqual(token, "tk_AgQd7")
        _, token = notify.channels(creds(self, "NOTIFY_URL=https://ntfy.sh/abc\nNOTIFY_TOKEN=tk bad\r\n"))
        self.assertIsNone(token)                                  # never a header with a space or CR in it


class NewsTest(unittest.TestCase):
    def setUp(self):
        self.c = mem_db()
        self.addCleanup(self.c.close)
        self.level = "warn"
        p = mock.patch.object(settings, "value", side_effect=lambda k: self.level if k == "notify_level" else None)
        p.start()
        self.addCleanup(p.stop)

    def evs(self, since=0):
        return [(n["ev"], n["text"]) for n in notify.news(self.c, NOW, since)]

    def test_what_is_news(self):
        alert(self.c, lv.WARN, "weak wifi", NOW - 60)
        alert(self.c, lv.BAD, "router hot", NOW - 900, cleared=NOW - 30)            # BAD, lasted 14.5 min
        alert(self.c, lv.BAD, "blip", NOW - 200, cleared=NOW - 100)                 # BAD but lasted 100 s
        alert(self.c, lv.WARN, "old", NOW - 4000)                                    # over an hour ago
        alert(self.c, lv.WARN, "new device", NOW - 10, kind="event")
        self.assertEqual(self.evs(), [("raise", "router hot"), ("raise", "blip"), ("raise", "weak wifi"),
                                      ("clear", "router hot"), ("raise", "new device")])   # in time order
        self.level = "bad"
        self.assertEqual(self.evs(), [("raise", "router hot"), ("raise", "blip"), ("clear", "router hot"),
                                      ("raise", "new device")])             # events whatever their level
        self.assertEqual(self.evs(since=NOW - 50), [("clear", "router hot"), ("raise", "new device")])


class MessageTest(unittest.TestCase):
    ITEMS = [{"id": 1, "ev": "raise", "level": lv.BAD, "text": "Office is 86 °C", "first": NOW, "cleared": None},
             {"id": 2, "ev": "clear", "level": lv.BAD, "text": "Internet down", "first": NOW - 1500, "cleared": NOW}]

    def test_ntfy_is_json_to_the_server_root_with_the_topic_inside(self):
        url, headers, body = notify.build(notify.NTFY, "https://ntfy.example.com/sub/my-topic", self.ITEMS,
                                          "http://192.168.1.60:8080/#/overview?item=alerts", "tk_x")
        self.assertEqual(url, "https://ntfy.example.com/sub/")
        self.assertEqual(headers, {"Authorization": "Bearer tk_x"})
        b = json.loads(body.decode("utf-8"))
        self.assertEqual((b["topic"], b["priority"], b["tags"]), ("my-topic", 4, ["rotating_light"]))
        self.assertEqual(b["title"], "Hearth: something needs you")
        self.assertEqual(b["message"], "Problem: Office is 86 °C\nCleared: Internet down (lasted 25 min)")
        self.assertEqual(b["click"], "http://192.168.1.60:8080/#/overview?item=alerts")
        url, headers, _ = notify.build(notify.NTFY, "https://ntfy.sh/t", self.ITEMS[1:])
        self.assertEqual((url, headers), ("https://ntfy.sh/", {}))

    def test_discord_slack_and_any_webhook(self):
        many = [{**self.ITEMS[0], "id": i, "text": "x" * 400} for i in range(12)]
        _, _, d = notify.build(notify.DISCORD, "https://discord.com/api/webhooks/1/x", many)
        content = json.loads(d)["content"]
        self.assertLessEqual(len(content), 2000)
        self.assertTrue(content.startswith("**Hearth: 12 things need you**"))
        _, _, s = notify.build(notify.SLACK, "https://hooks.slack.com/services/x", self.ITEMS, "http://h/#/x")
        self.assertIn("<http://h/#/x|Open Hearth>", json.loads(s)["text"])
        _, _, w = notify.build(notify.WEBHOOK, "http://10.0.0.2/hook", many)
        w = json.loads(w)
        self.assertEqual((len(w["alerts"]), w["more"], w["level"]), (notify.LINES_MAX, 4, lv.BAD))
        self.assertTrue(w["text"].endswith("and 4 more - see Hearth"))

    def test_only_clears(self):
        title, lines, worst = notify.compose(self.ITEMS[1:])
        self.assertEqual((title, worst), ("Hearth: cleared", None))


class RunTest(unittest.TestCase):
    def setUp(self):
        self.c = mem_db()
        self.addCleanup(self.c.close)
        p = mock.patch.object(settings, "value", side_effect=lambda k: {"notify_level": "warn"}.get(k))
        p.start()
        self.addCleanup(p.stop)

    def path(self, *urls):
        return creds(self, "".join(f"{k}={u}\n" for k, u in zip(notify.URL_KEYS, urls)))

    def test_not_set_up(self):
        self.assertEqual(notify.run(self.c, NOW, self.path()), {})
        self.assertFalse(sources.read(self.c, sources.NOTIFY)["configured"])

    def test_sends_what_is_new_once_and_never_what_came_before(self):
        rx = Receiver(self)
        path = self.path(rx.url)
        alert(self.c, lv.BAD, "from before", NOW - 30)
        self.assertEqual(notify.run(self.c, NOW, path), {"NOTIFY_URL": "nothing"})    # first sight: a baseline
        alert(self.c, lv.WARN, "weak wifi", NOW + 10)
        alert(self.c, lv.BAD, "router hot", NOW + 10)
        self.assertEqual(notify.run(self.c, NOW + 20, path), {"NOTIFY_URL": "sent"})
        self.assertEqual(notify.run(self.c, NOW + 50, path), {"NOTIFY_URL": "nothing"})   # said once
        self.assertEqual(len(rx.posts), 1)
        where, headers, body = rx.posts[0]
        self.assertEqual(where, "/hook/secret-token")
        self.assertEqual([a["text"] for a in body["alerts"]], ["weak wifi", "router hot"])
        st = sources.read(self.c, sources.NOTIFY)
        self.assertTrue(st["ok"])
        self.assertEqual(st["detail"], {"channels": ["webhook"]})

    def test_a_failing_channel_retries_later_and_never_blocks_or_repeats_the_other(self):
        good, bad = Receiver(self), Receiver(self, status=500)
        path = self.path(good.url, bad.url)
        notify.run(self.c, NOW, path)
        alert(self.c, lv.BAD, "router hot", NOW + 10)
        self.assertEqual(notify.run(self.c, NOW + 20, path), {"NOTIFY_URL": "sent", "NOTIFY_URL_2": "failed"})
        st = sources.read(self.c, sources.NOTIFY)
        self.assertFalse(st["ok"])
        self.assertEqual(st["error"], "webhook: HTTP 500")
        self.assertNotIn("secret-token", json.dumps(st))           # the address is a secret
        self.assertEqual(notify.run(self.c, NOW + 30, path)["NOTIFY_URL_2"], "waiting")   # retried after 1 min
        bad.status = 204
        self.assertEqual(notify.run(self.c, NOW + 90, path), {"NOTIFY_URL": "nothing", "NOTIFY_URL_2": "sent"})
        self.assertEqual((len(good.posts), len(bad.posts)), (1, 2))
        self.assertTrue(sources.read(self.c, sources.NOTIFY)["ok"])

    def test_at_most_six_an_hour_then_the_rest_together(self):
        rx = Receiver(self)
        path = self.path(rx.url)
        notify.run(self.c, NOW, path)
        for i in range(8):
            alert(self.c, lv.WARN, f"problem {i}", NOW + 100 * i + 1)
            notify.run(self.c, NOW + 100 * i + 2, path)
        self.assertEqual(len(rx.posts), 6)
        self.assertEqual(notify.run(self.c, NOW + 3602, path)["NOTIFY_URL"], "sent")   # the first send left the hour
        self.assertEqual([a["text"] for a in rx.posts[-1][2]["alerts"]], ["problem 6", "problem 7"])

    def test_old_news_is_dropped_not_sent_late(self):
        rx = Receiver(self, status=503)
        path = self.path(rx.url)
        notify.run(self.c, NOW, path)
        alert(self.c, lv.BAD, "router hot", NOW + 10)
        notify.run(self.c, NOW + 20, path)
        rx.status = 204
        self.assertEqual(notify.run(self.c, NOW + 20 + notify.WINDOW_S, path)["NOTIFY_URL"], "nothing")

    def test_a_redirect_is_refused(self):
        rx = Receiver(self, redirect="http://192.168.1.1/admin")
        path = self.path(rx.url)
        notify.run(self.c, NOW, path)
        alert(self.c, lv.BAD, "router hot", NOW + 10)
        self.assertEqual(notify.run(self.c, NOW + 20, path)["NOTIFY_URL"], "failed")
        self.assertEqual(sources.read(self.c, sources.NOTIFY)["error"], "webhook: HTTP 302")
        self.assertEqual(len(rx.posts), 1)                          # never followed

    def test_a_garbled_reply_fails_that_channel_only(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        self.addCleanup(srv.close)

        def answer():
            conn, _ = srv.accept()
            got = b""                    # the whole request first: closing on an unread body resets it
            while b"\r\n\r\n" not in got:
                got += conn.recv(65536)
            head, _, body = got.partition(b"\r\n\r\n")
            size = int(next(ln.split(b":")[1] for ln in head.split(b"\r\n") if ln.lower().startswith(b"content-length")))
            while len(body) < size:
                body += conn.recv(65536)
            conn.sendall(b"garbage\r\n\r\n")
            conn.close()
        threading.Thread(target=answer, daemon=True).start()
        good = Receiver(self)
        path = self.path(f"http://127.0.0.1:{srv.getsockname()[1]}/hook", good.url)
        notify.run(self.c, NOW, path)
        alert(self.c, lv.BAD, "router hot", NOW + 10)
        self.assertEqual(notify.run(self.c, NOW + 20, path), {"NOTIFY_URL": "failed", "NOTIFY_URL_2": "sent"})
        self.assertEqual(sources.read(self.c, sources.NOTIFY)["error"], "webhook: bad reply or address (BadStatusLine)")

    def test_a_failure_stops_counting_once_its_news_has_gone(self):
        rx = Receiver(self, status=500)
        path = self.path(rx.url)
        notify.run(self.c, NOW, path)
        alert(self.c, lv.BAD, "router hot", NOW + 10)
        notify.run(self.c, NOW + 20, path)
        self.assertFalse(sources.read(self.c, sources.NOTIFY)["ok"])
        notify.run(self.c, NOW + 20 + notify.WINDOW_S, path)          # the news is over an hour old
        self.assertTrue(sources.read(self.c, sources.NOTIFY)["ok"])

    def test_an_unusable_address_is_a_failing_channel(self):
        self.assertEqual(notify.run(self.c, NOW, self.path("ftp://x/y")), {"NOTIFY_URL": "failed"})
        st = sources.read(self.c, sources.NOTIFY)
        self.assertEqual((st["ok"], st["error"]), (False, "NOTIFY_URL: not a usable address"))

    def test_unreachable(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()                                           # a port nothing listens on
        path = self.path(f"http://127.0.0.1:{port}/hook/secret-token")
        notify.run(self.c, NOW, path)
        alert(self.c, lv.BAD, "router hot", NOW + 10)
        self.assertEqual(notify.run(self.c, NOW + 20, path)["NOTIFY_URL"], "failed")
        err = sources.read(self.c, sources.NOTIFY)["error"]
        self.assertRegex(err, r"^webhook: (couldn't connect \(\w+\)|timed out)$")   # never the address


class SendATestTest(unittest.TestCase):
    """Step 6.2: Setup's "Send a test"."""

    def setUp(self):
        notify._test["at"] = 0.0
        self.addCleanup(notify._test.update, at=0.0)
        p = mock.patch.object(settings, "value", return_value=None)
        p.start()
        self.addCleanup(p.stop)

    def test_each_channel_gets_a_fixed_message_at_most_once_a_minute(self):
        good, bad = Receiver(self), Receiver(self, status=403)
        path = creds(self, f"NOTIFY_URL={good.url}\nNOTIFY_URL_2={bad.url}\n")
        out = notify.test(path, now=NOW)
        self.assertEqual(out, {"results": [{"kind": "webhook", "ok": True, "error": None},
                                           {"kind": "webhook", "ok": False, "error": "HTTP 403"}]})
        self.assertEqual(good.posts[0][2]["text"], "Warning: Hearth test: notifications work.")
        self.assertNotIn("secret-token", json.dumps(out))
        with self.assertRaises(notify.Busy):
            notify.test(path, now=NOW + 30)
        self.assertEqual(len(notify.test(path, now=NOW + 61)["results"]), 2)

    def test_nothing_set_up(self):
        self.assertEqual(notify.test(creds(self, ""), now=NOW), {"results": []})


class TestEndpointTest(unittest.TestCase):
    def setUp(self):
        from hearth.web import Handler
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)

    def post(self, origin=None):
        import http.client
        port = self.srv.server_address[1]
        h = {"Content-Type": "application/json", "Origin": origin or f"http://127.0.0.1:{port}"}
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        self.addCleanup(conn.close)
        conn.request("POST", "/api/notify/test", body=b"{}", headers=h)
        r = conn.getresponse()
        return r.status, json.loads(r.read())

    def test_same_origin_and_busy(self):
        with mock.patch.object(notify, "test", return_value={"results": []}) as t:
            self.assertEqual(self.post(), (200, {"results": []}))
            self.assertEqual(self.post(origin="http://evil.example")[0], 403)   # another site can't press it
            self.assertEqual(t.call_count, 1)
        with mock.patch.object(notify, "test", side_effect=notify.Busy("a test was sent under a minute ago")):
            self.assertEqual(self.post(), (429, {"error": "a test was sent under a minute ago"}))


class SettingsTest(unittest.TestCase):
    def test_notify_level_and_dashboard_address(self):
        lvl, url = settings.EDITABLE["notify_level"], settings.EDITABLE["dashboard_url"]
        self.assertEqual([lvl("warn", {}), lvl("bad", {})], ["warn", "bad"])
        self.assertEqual([url("http://192.168.1.60:8080/", {}), url("https://hearth.local", {}), url("", {}),
                          url("http://host/hearth/", {})],
                         ["http://192.168.1.60:8080", "https://hearth.local", "", "http://host/hearth"])   # a plain path is kept
        for v in ("info", None, 3):
            with self.assertRaises(settings.Invalid):
                lvl(v, {})
        for v in ("javascript:alert(1)", "http://x/#/evil", "http://a b", "ftp://x", "http://x/p?q=1",
                  "http://user@x", 5):
            with self.assertRaises(settings.Invalid, msg=v):
                url(v, {})


class LinkTest(unittest.TestCase):
    def test_link_only_with_a_dashboard_address(self):
        for base, want in (("http://192.168.1.60:8080", "http://192.168.1.60:8080/#/overview?item=alerts"),
                           ("http://hearth.local:8080/", "http://hearth.local:8080/#/overview?item=alerts"),
                           ("http://host/hearth", "http://host/hearth/#/overview?item=alerts"),   # #121 review
                           ("", None), ("javascript:x", None), (None, None)):
            with mock.patch.object(settings, "value", return_value=base):
                self.assertEqual(notify.link(), want)


class StoreTest(unittest.TestCase):
    def test_state_rows_never_carry_the_address(self):
        c = mem_db()
        self.addCleanup(c.close)
        with mock.patch.object(settings, "value", return_value=None):
            notify.run(c, NOW, creds(self, "NOTIFY_URL=https://ntfy.sh/secret-topic\n"))
        rows = json.dumps(list(c.execute("SELECT * FROM state")))
        self.assertNotIn("secret-topic", rows)
        self.assertIsNotNone(store.get_state(c, notify.STATE_PREFIX + "NOTIFY_URL"))


if __name__ == "__main__":
    unittest.main()
