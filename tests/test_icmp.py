"""Linux ICMP "ping sockets" (#2): the packet helpers run everywhere; the real-socket tests run on
Linux wherever net.ipv4.ping_group_range lets this user open one (GitHub's Ubuntu runners,
Docker containers)."""
import platform
import socket
import struct
import unittest

from hearth import net


def ping_sockets_allowed():
    if platform.system() != "Linux":
        return False
    try:
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP).close()
        return True
    except OSError:
        return False


class PacketHelpersTest(unittest.TestCase):
    def test_echo_request_leaves_id_and_checksum_to_the_kernel(self):
        pkt = net.build_echo(0x1234)
        self.assertEqual(struct.unpack("!BBHHH", pkt[:8]), (8, 0, 0, 0, 0x1234))
        self.assertEqual(net.echo_seq(pkt), 0x1234)
        self.assertEqual(net.echo_seq(net.build_echo(0x1FFFF)), 0xFFFF)  # wraps at 16 bits

    def test_reply_must_match_type_and_sequence(self):
        reply = struct.pack("!BBHHH", 0, 0, 0xBEEF, 7, 42) + b"x"
        self.assertTrue(net.is_echo_reply(reply, 42))
        self.assertFalse(net.is_echo_reply(reply, 43))                       # someone else's probe
        self.assertFalse(net.is_echo_reply(struct.pack("!BBHHH", 8, 0, 0, 7, 42), 42))  # a request
        self.assertFalse(net.is_echo_reply(b"\x00\x00", 42))                 # truncated

    def test_recverr_gives_the_router_that_answered(self):
        # struct sock_extended_err: errno, origin (2 = ICMP), type 11 (time exceeded), code, pad,
        # info, data; then sockaddr_in of the router
        ee = struct.pack("=IBBBBII", 113, 2, 11, 0, 0, 0, 0)
        sin = struct.pack("=HH4s8x", socket.AF_INET, 0, socket.inet_aton("192.168.1.254"))
        self.assertEqual(net.parse_recverr(ee + sin), (2, 11, 0, "192.168.1.254"))
        self.assertEqual(net.parse_recverr(ee), (2, 11, 0, None))           # no address attached
        self.assertIsNone(net.parse_recverr(b"short"))


@unittest.skipUnless(platform.system() == "Linux", "the socket pinger is Linux only")
class PingerChoiceTest(unittest.TestCase):
    def test_other_socket_errors_dont_blame_ping_group_range(self):
        import errno
        from unittest import mock
        with mock.patch.object(net, "_SocketPinger", side_effect=OSError(errno.EMFILE, "Too many open files")), \
                mock.patch.object(net, "_socket_errors_logged", set()), \
                mock.patch.object(net, "log") as log:
            p = net.Pinger()
        self.assertEqual(type(p).__name__, "_ProcessPinger")
        msg = log.call_args.args[0]
        self.assertIn("Too many open files", msg)
        self.assertNotIn("ping_group_range", msg)

    def test_a_lasting_socket_error_is_logged_once(self):
        import errno
        from unittest import mock
        with mock.patch.object(net, "_SocketPinger", side_effect=OSError(errno.EAFNOSUPPORT, "not supported")), \
                mock.patch.object(net, "_socket_errors_logged", set()), \
                mock.patch.object(net, "log") as log:
            for _ in range(5):
                net.Pinger()
        self.assertEqual(log.call_count, 1)

    def test_a_socket_that_keeps_failing_gives_up_early(self):
        if not ping_sockets_allowed():
            self.skipTest("needs ping sockets")
        import time
        from unittest import mock
        p = net.Pinger()
        self.addCleanup(p.close)
        p.poller = mock.Mock(poll=mock.Mock(return_value=[(p.s.fileno(), 8)]))   # always "ready"
        p.s = mock.Mock(wraps=p.s, recvmsg=mock.Mock(side_effect=OSError(5, "I/O error")),
                        recv=mock.Mock(side_effect=OSError(5, "I/O error")),
                        sendto=p.s.sendto, setsockopt=p.s.setsockopt)
        t = time.perf_counter()
        self.assertIsNone(p.ping("127.0.0.1", 5000))
        self.assertLess(time.perf_counter() - t, 1.0)  # gave up long before the 5 s timeout


@unittest.skipUnless(ping_sockets_allowed(), "needs Linux with ping sockets allowed (ping_group_range)")
class PingSocketTest(unittest.TestCase):
    def setUp(self):
        self.p = net.Pinger()
        self.addCleanup(self.p.close)

    def test_uses_a_socket_and_answers_locally(self):
        self.assertEqual(type(self.p).__name__, "_SocketPinger")
        rtts = [self.p.ping("127.0.0.1", 1000) for _ in range(5)]
        self.assertTrue(all(r is not None and r >= 0 for r in rtts), rtts)

    def test_no_answer_times_out(self):
        self.assertIsNone(self.p.ping("192.0.2.1", 300))  # TEST-NET-1: never answers

    def test_hop_to_a_local_address_is_the_address_itself(self):
        self.assertEqual(self.p.hop("127.0.0.1", 1, 1000)[0], "127.0.0.1")

    def test_works_with_a_descriptor_above_1024(self):
        # select() can't watch descriptors >= 1024; a long-running server can get there
        import resource
        soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft < 1200:
            self.skipTest("open-file limit too low to get past descriptor 1024")
        held = []
        try:
            while not held or held[-1].fileno() < 1030:
                held.append(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
            p = net.Pinger()
            self.addCleanup(p.close)
            self.assertGreaterEqual(p.s.fileno(), 1024)
            self.assertIsNotNone(p.ping("127.0.0.1", 1000))
        finally:
            for s in held:
                s.close()

    def test_one_pinger_shared_by_threads_keeps_replies_apart(self):
        import threading
        results = []

        def worker():
            results.extend(self.p.ping("127.0.0.1", 1000) is not None for _ in range(20))
        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(results.count(True), 80)


if __name__ == "__main__":
    unittest.main()
