"""Step 4, part 3a (#88): the DNS check - the packet, the probe, which resolvers may be asked,
what's stored, and what the page and "Needs attention" are told."""
import ipaddress
import socket
import struct
import threading
import time
import unittest
from unittest import mock

from hearth import analysis, collectors, dns, dns_health, levels as lv, overview, sources, store
from tests.helpers import mem_db

LAN = ipaddress.ip_network("192.168.1.0/24")
GW = "192.168.1.254"


class PacketTest(unittest.TestCase):
    def test_a_standard_query(self):
        q = dns.build_query("www.google.com", 0x1234)
        self.assertEqual(struct.unpack(">HHHHHH", q[:12]), (0x1234, 0x0100, 1, 0, 0, 0))
        self.assertEqual(q[12:], b"\x03www\x06google\x03com\x00" + struct.pack(">HH", 1, 1))

    def test_names_hearth_wont_ask_for(self):
        for bad in ("", "a..b", "-a.com", "a-.com", "a" * 64 + ".com", "x" * 254, "a b.com", "ü.com", None, 5):
            self.assertFalse(dns.valid_name(bad), bad)
            with self.assertRaises(ValueError):
                dns.build_query(bad, 1)
        self.assertTrue(dns.valid_name("a" * 63 + ".com."))

    def test_only_the_header_of_a_matching_response_counts(self):
        reply = lambda qid, flags: struct.pack(">HHHHHH", qid, flags, 1, 1, 0, 0) + b"junk"   # noqa: E731
        self.assertEqual(dns.parse_reply(reply(7, 0x8180), 7), 0)            # answered
        self.assertEqual(dns.parse_reply(reply(7, 0x8183), 7), 3)            # no such name
        self.assertIsNone(dns.parse_reply(reply(8, 0x8180), 7))              # another question's
        self.assertIsNone(dns.parse_reply(reply(7, 0x0100), 7))              # a query, not a response
        self.assertIsNone(dns.parse_reply(b"\x00\x07\x81", 7))               # truncated
        self.assertIsNone(dns.parse_reply(None, 7))


class FakeResolver:
    """A UDP resolver on localhost: first a spoofed reply (wrong ID), then the real one."""

    def __init__(self, rcode=0, answer=True):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.rcode, self.answer = rcode, answer
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        data, addr = self.sock.recvfrom(512)
        qid = struct.unpack(">H", data[:2])[0]
        self.sock.sendto(struct.pack(">HHHHHH", (qid + 1) & 0xFFFF, 0x8180, 1, 0, 0, 0), addr)
        if self.answer:
            self.sock.sendto(struct.pack(">HHHHHH", qid, 0x8180 | self.rcode, 1, 0, 0, 0), addr)

    def close(self):
        self.sock.close()


class ProbeTest(unittest.TestCase):
    def probe(self, **kw):
        fake = FakeResolver(**kw)
        self.addCleanup(fake.close)
        with mock.patch.object(dns, "PORT", fake.port):
            return dns.probe("127.0.0.1", "www.google.com", timeout=0.5)

    def test_the_matching_reply_is_timed_and_a_spoofed_one_ignored(self):
        ms, rcode = self.probe()
        self.assertEqual(rcode, 0)
        self.assertGreaterEqual(ms, 0)

    def test_the_rcode_is_kept(self):
        self.assertEqual(self.probe(rcode=5)[1], 5)

    def test_no_real_answer_is_no_answer(self):
        self.assertEqual(self.probe(answer=False), (None, None))   # the spoofed reply alone doesn't count


class WhoMayBeAskedTest(unittest.TestCase):
    def test_the_router_the_lan_and_six_public_resolvers_only(self):
        for ok in (GW, "192.168.1.53", *dns.PUBLIC_RESOLVERS):
            self.assertTrue(dns.allowed(ok, GW, LAN), ok)
        for bad in ("10.0.0.1", "192.168.1.0", "192.168.1.255", "4.4.4.4", "8.8.8.9", "::1", "localhost", "", None):
            self.assertFalse(dns.allowed(bad, GW, LAN), bad)
        self.assertFalse(dns.allowed("192.168.1.53", GW, None))        # no LAN known: only router and public

    def test_resolvers_in_order_without_repeats_at_most_three(self):
        got, refused = dns.resolvers(["gateway", "1.1.1.1", GW, "10.0.0.1", "8.8.8.8", "9.9.9.9"], GW, LAN)
        self.assertEqual(got, [GW, "1.1.1.1", "8.8.8.8"])
        self.assertEqual(refused, ["10.0.0.1"])
        self.assertEqual(dns.resolvers(["gateway", "1.1.1.1"], None, LAN), (["1.1.1.1"], []))   # no router known yet
        self.assertEqual(dns.resolvers("1.1.1.1", GW, LAN), ([], []))                            # not a list


class StoreTest(unittest.TestCase):
    def setUp(self):
        self.c = mem_db()
        self.addCleanup(self.c.close)
        self.now = int(time.time()) // 60 * 60

    def test_answers_are_stored_and_the_source_reports(self):
        collectors.record_dns(self.c, self.now, [(GW, 6.5, 0), ("1.1.1.1", None, None)], [])
        self.assertEqual(self.c.execute("SELECT resolver, ms, rcode FROM dns_1m ORDER BY resolver").fetchall(),
                         [("1.1.1.1", None, None), (GW, 6.5, 0)])
        self.assertTrue(sources.read(self.c, sources.DNS)["ok"])
        collectors.record_dns(self.c, self.now + 60, [(GW, None, None)], [])
        self.assertEqual(sources.read(self.c, sources.DNS)["error"], dns_health.NO_ANSWER)
        collectors.record_dns(self.c, self.now + 120, [], ["10.0.0.1"])
        st = sources.read(self.c, sources.DNS)
        self.assertIn("no resolver Hearth may ask", st["error"])
        self.assertEqual(st["detail"]["refused"], ["10.0.0.1"])


class ViewAndAttentionTest(unittest.TestCase):
    def setUp(self):
        self.c = mem_db()
        self.addCleanup(self.c.close)
        p = mock.patch.object(analysis, "_gateway_ip", return_value=GW)
        p.start()
        self.addCleanup(p.stop)
        self.now = int(time.time()) // 60 * 60

    def rows(self, resolver, values, end=None):
        end = end or self.now
        self.c.executemany("INSERT INTO dns_1m VALUES (?, ?, ?, ?)",
                           [(end - 60 * (len(values) - 1 - i), resolver, ms, None if ms is None else 0)
                            for i, ms in enumerate(values)])

    def test_the_view(self):
        self.rows(GW, [5.0, 7.0, None, 9.0])
        self.rows("1.1.1.1", [15.0] * 4)
        v = dns_health.dns_view(self.c, 15)
        r = v["resolvers"]
        self.assertEqual([x["name"] for x in r], ["Your router", "1.1.1.1"])      # the router first
        self.assertEqual((r[0]["asked"], r[0]["fail_pct"], r[0]["p50_ms"]), (4, 25.0, 7.0))
        self.assertEqual(r[0]["level"], lv.BAD)                                   # 25% unanswered
        self.assertEqual(r[1]["level"], lv.OK)
        self.assertEqual(len(r[0]["series"]), 3)

    def test_nothing_recent_says_nothing(self):
        self.assertEqual(dns_health.attention(self.c, self.now), [])

    def test_nothing_answering(self):
        self.rows(GW, [None, None, None])
        self.rows("1.1.1.1", [None, None, None])
        [(level, text)] = dns_health.attention(self.c, self.now)
        self.assertEqual(level, lv.BAD)
        self.assertIn("DNS isn't answering", text)

    def test_only_the_router_failing_points_at_the_router(self):
        self.rows(GW, [None, None, None])
        self.rows("1.1.1.1", [15.0, 16.0, 15.0])
        [(level, text)] = dns_health.attention(self.c, self.now)
        self.assertIn("Your router isn't answering DNS questions (1.1.1.1 is)", text)

    def test_a_slow_router(self):
        self.rows(GW, [450.0] * 10)
        self.rows("1.1.1.1", [15.0] * 10)
        [(level, text)] = dns_health.attention(self.c, self.now)
        self.assertEqual(level, lv.WARN)
        self.assertIn("slow (450 ms an answer)", text)

    def test_needs_attention_says_it_once(self):
        # nothing answering fails the source too; "Needs attention" words it once, as DNS
        self.rows(GW, [None, None, None])
        sources.report_error(self.c, sources.DNS, dns_health.NO_ANSWER)
        texts = [i["text"] for i in overview.attention(self.c, self.now)]
        self.assertEqual(sum("DNS" in t for t in texts), 1, texts)
        self.assertEqual([i["item"] for i in overview.attention(self.c, self.now) if "DNS" in i["text"]], ["src:dns"])


class LevelTest(unittest.TestCase):
    def test_dns_level(self):
        self.assertEqual(lv.dns_level({})["level"], lv.UNKNOWN)
        self.assertEqual(lv.dns_level({"asked": 5, "fail_pct": 0, "p50_ms": 20})["level"], lv.OK)
        self.assertEqual(lv.dns_level({"asked": 5, "fail_pct": 0, "p50_ms": 300})["level"], lv.WARN)
        self.assertEqual(lv.dns_level({"asked": 5, "fail_pct": 5, "p50_ms": 20})["level"], lv.WARN)
        self.assertEqual(lv.dns_level({"asked": 5, "fail_pct": 100, "p50_ms": None})["level"], lv.BAD)


class RetentionTest(unittest.TestCase):
    def test_kept_as_long_as_events(self):
        c = mem_db()
        self.addCleanup(c.close)
        old = time.time() - 91 * 86400
        c.execute("INSERT INTO dns_1m VALUES (?, ?, ?, ?)", (old, GW, 5.0, 0))
        with mock.patch.dict(store.CFG, {"retention_days": 90}):
            store.prune(c, time.time())
        self.assertEqual(c.execute("SELECT COUNT(*) FROM dns_1m").fetchone()[0], 0)



class EpisodeContextTest(unittest.TestCase):
    """#101: an episode while the router's DNS was failing or slow says so."""

    def setUp(self):
        from hearth import analysis
        self.analysis = analysis
        self.c = mem_db()
        self.addCleanup(self.c.close)
        p = mock.patch.object(analysis, "_gateway_ip", return_value=GW)
        p.start()
        self.addCleanup(p.stop)

    def dns(self, ts, ms, rcode=0):
        self.c.execute("INSERT INTO dns_1m VALUES (?, ?, ?, ?)", (ts, GW, ms, rcode))

    def test_failing_slow_and_fine(self):
        e = lambda s: {"start": s, "end": s + 60, "kind": "slow", "context": ["x"]}   # noqa: E731
        self.dns(1000, None, None)                 # didn't answer during the first
        self.dns(5000, 600.0)                      # slow during the second
        self.dns(9000, 8.0)                        # fine during the third
        out = self.analysis.with_dns_context(self.c, [e(1000), e(5000), e(9000), e(20000)], 0, 30000)
        self.assertIn("didn't answer then", out[0]["context"][-1])
        self.assertIn("was slow then (600 ms an answer)", out[1]["context"][-1])
        self.assertEqual(out[2]["context"], ["x"])
        self.assertEqual(out[3]["context"], ["x"])                  # no DNS reading near it: nothing said


if __name__ == "__main__":
    unittest.main()
