import unittest

from hearth import collectors, store
from hearth.config import KEEP_SWEEPS, OFFLINE_AFTER_MISSES, STATE_ASLEEP, STATE_OFFLINE, STATE_ONLINE
from hearth.naming import ROUTER_FRESH_S, asleep_cutoff, device_rows, device_state, router_offline
from tests.helpers import mem_db

PC, PC_MAC = "192.168.1.228", "60:cf:84:5e:00:02"
T0 = 1_792_000_000.0
SWEEP = 300


class PresenceTest(unittest.TestCase):
    def setUp(self):
        self.c = mem_db()
        self.addCleanup(self.c.close)
        self.missed = {}

    def sweep(self, n, seen=(), answered=(), mac=PC_MAC):
        """Sweep number n, recorded as discovery_loop does: `seen` were on the network (ping or
        ARP), `answered` replied to ping."""
        seen = set(seen) | set(answered)
        start = T0 + n * SWEEP
        self.missed = collectors.record_sweep(self.c, seen, set(answered), {ip: mac for ip in seen},
                                              {ip: "GamingPC.lan" for ip in seen}, set(), self.missed, start + 30)
        self.c.execute("INSERT INTO sweeps VALUES (?,?)", (start, start + 20))

    def events(self, kind):
        return [d for (d,) in self.c.execute("SELECT detail FROM events WHERE kind=? ORDER BY ts", (kind,))]

    def online(self):
        return self.c.execute("SELECT online FROM devices WHERE ip=?", (PC,)).fetchone()[0]

    def state(self):
        [row] = device_rows(self.c)
        return row[11]

    def test_one_missed_sweep_is_not_offline(self):
        self.sweep(0, answered=[PC])
        self.sweep(1)                      # e.g. its ARP answer didn't land this time
        self.assertEqual(self.online(), 1)
        self.sweep(2, answered=[PC])
        self.assertEqual(self.events("device_offline"), [])
        self.assertEqual(self.events("device_online"), [])

    def test_offline_after_misses_says_when_last_seen(self):
        self.sweep(0, answered=[PC])
        for n in range(1, OFFLINE_AFTER_MISSES + 1):
            self.sweep(n)
        self.assertEqual(self.online(), 0)
        [ev] = self.events("device_offline")
        self.assertIn("GamingPC.lan went offline (last seen ", ev)
        self.assertEqual(self.missed, {})
        self.sweep(OFFLINE_AFTER_MISSES + 1, answered=[PC])
        self.assertEqual(self.events("device_online"), ["GamingPC.lan came online"])

    def test_misses_must_be_in_a_row(self):
        self.sweep(0, answered=[PC])
        for n in range(1, 8):
            self.sweep(n, answered=[PC] if n % 2 == 0 else [])  # missing every other sweep
        self.assertEqual(self.online(), 1)
        self.assertEqual(self.events("device_offline"), [])

    def test_counts_are_returned_not_changed_in_place(self):
        # discovery_loop keeps the returned counts only if the writes commit
        self.sweep(0, answered=[PC])
        before = {PC: 0}
        after = collectors.record_sweep(self.c, set(), set(), {}, {}, set(), before, T0 + SWEEP)
        self.assertEqual(before, {PC: 0})
        self.assertEqual(after, {PC: 1})

    def test_forgotten_device_is_not_counted(self):
        self.sweep(0, answered=[PC])
        self.c.execute("DELETE FROM devices")
        out = collectors.record_sweep(self.c, set(), set(), {}, {}, set(), {PC: 1}, T0 + SWEEP)
        self.assertEqual(out, {})

    def test_only_ping_moves_last_answered(self):
        self.sweep(0, answered=[PC])
        self.sweep(1, seen=[PC])           # in ARP, not answering ping
        self.assertEqual(self.c.execute("SELECT last_answered, last_seen FROM devices").fetchone(),
                         (T0 + 30, T0 + SWEEP + 30))

    def test_new_device_on_the_ip_starts_without_ping_history(self):
        self.sweep(0, answered=[PC])
        self.sweep(1, seen=[PC], mac="aa:bb:cc:dd:ee:ff")  # DHCP gave the address to another device
        self.assertIsNone(self.c.execute("SELECT last_answered FROM devices").fetchone()[0])

    def test_asleep_after_keep_sweeps_without_ping(self):
        self.sweep(0, answered=[PC])
        for n in range(1, KEEP_SWEEPS):
            self.sweep(n, seen=[PC])
            self.assertEqual(self.state(), STATE_ONLINE)  # answered within the last KEEP_SWEEPS sweeps
        self.sweep(KEEP_SWEEPS, seen=[PC])
        self.assertEqual(self.state(), STATE_ASLEEP)
        self.sweep(KEEP_SWEEPS + 1, answered=[PC])        # woke up
        self.assertEqual(self.state(), STATE_ONLINE)

    def test_no_sweeps_running_changes_nothing(self):
        # judged by sweeps, not the clock: however long until the next sweep, still online
        self.sweep(0, answered=[PC])
        self.assertEqual(self.state(), STATE_ONLINE)
        self.assertIsNone(asleep_cutoff(self.c))  # fewer than KEEP_SWEEPS sweeps so far


class IdChangeTest(unittest.TestCase):
    """#3: a device whose MAC becomes shared (or stops being) keeps its history and name."""
    A, B, MAC = "192.168.1.10", "192.168.1.11", "aa:bb:cc:00:00:01"

    def setUp(self):
        self.c = mem_db()
        self.addCleanup(self.c.close)
        self.missed, self.n = {}, 0

    def sweep(self, arp, n=None):
        """One sweep, with sharing judged as discovery_loop does (present devices)."""
        self.n = self.n + 1 if n is None else n
        seen = set(arp)
        still = dict(self.c.execute("SELECT ip, mac FROM devices WHERE online=1"))
        shared = collectors.shared_mac_ips(seen, arp, still)
        self.missed = collectors.record_sweep(self.c, seen, seen, arp, {ip: None for ip in seen}, shared,
                                              self.missed, T0 + self.n * SWEEP)

    def gone_sweeps(self, arp):
        """Enough sweeps with only `arp` present for the missing devices to be marked offline
        and then no longer count as present."""
        for _ in range(OFFLINE_AFTER_MISSES + 1):
            self.sweep(arp)

    def history(self, tid):
        return (self.c.execute("SELECT COUNT(*) FROM pings WHERE target=?", (tid,)).fetchone()[0],
                self.c.execute("SELECT COUNT(*) FROM pings_1m WHERE target=?", (tid,)).fetchone()[0])

    def seed(self, tid):
        self.c.executemany("INSERT INTO pings VALUES (?,?,?)", [(T0 + i, tid, 5.0) for i in range(3)])
        self.c.execute("INSERT INTO pings_1m (ts, target, n, lost, avg, max) VALUES (?,?,12,0,5.0,6.0)", (int(T0 // 60 * 60), tid))
        self.c.execute("INSERT INTO labels VALUES (?, 'Lounge PC')", (tid,))

    def test_mac_becomes_shared_history_follows_its_owner(self):
        self.sweep({self.A: self.MAC}, 0)
        self.seed(f"dev:{self.MAC}")
        self.sweep({self.A: self.MAC, self.B: self.MAC}, 1)    # a repeater now answers for B with A's MAC
        self.assertEqual(self.history(f"dev:ip:{self.A}"), (3, 1))
        self.assertEqual(self.history(f"dev:{self.MAC}"), (0, 0))
        self.assertEqual(self.history(f"dev:ip:{self.B}"), (0, 0))  # the newcomer gets nothing
        self.assertEqual(dict(self.c.execute("SELECT key, name FROM labels")), {f"dev:ip:{self.A}": "Lounge PC"})

    def test_mac_stops_being_shared_history_goes_back(self):
        self.sweep({self.A: self.MAC, self.B: self.MAC}, 0)
        self.seed(f"dev:ip:{self.A}")
        self.gone_sweeps({self.A: self.MAC})                   # B has really left, not just missed a sweep
        self.assertEqual(self.history(f"dev:{self.MAC}"), (3, 1))
        self.assertEqual(dict(self.c.execute("SELECT key, name FROM labels")), {f"dev:{self.MAC}": "Lounge PC"})

    def test_ambiguous_owner_moves_nothing(self):
        # two IPs both recorded with the MAC before it was seen as shared: whose history is it?
        self.c.executemany("INSERT INTO devices (ip, mac, online, last_seen) VALUES (?,?,1,?)",
                           [(self.A, self.MAC, T0), (self.B, self.MAC, T0)])
        self.seed(f"dev:{self.MAC}")
        self.sweep({self.A: self.MAC, self.B: self.MAC}, 1)
        self.assertEqual(self.history(f"dev:{self.MAC}"), (3, 1))

    C = "192.168.1.12"

    def test_shared_ip_going_offline_moves_nothing(self):
        self.sweep({self.A: self.MAC, self.B: self.MAC, self.C: self.MAC}, 0)
        self.seed(f"dev:ip:{self.C}")
        self.sweep({self.A: self.MAC, self.B: self.MAC}, 1)      # C just went offline
        self.assertEqual(self.history(f"dev:ip:{self.C}"), (3, 1))
        self.assertEqual(self.history(f"dev:{self.MAC}"), (0, 0))
        self.sweep({self.A: self.MAC, self.B: self.MAC, self.C: self.MAC}, 2)  # and came back
        self.assertEqual(self.history(f"dev:ip:{self.C}"), (3, 1))

    def test_three_collapsing_to_one_moves_only_the_one_still_there(self):
        self.sweep({self.A: self.MAC, self.B: self.MAC, self.C: self.MAC}, 0)
        for ip in (self.A, self.B, self.C):
            self.c.executemany("INSERT INTO pings VALUES (?,?,?)", [(T0 + i, f"dev:ip:{ip}", 5.0) for i in range(2)])
        self.gone_sweeps({self.A: self.MAC})                      # B and C gone, A alone with the MAC
        self.assertEqual(self.history(f"dev:{self.MAC}")[0], 2)   # A's two pings, nobody else's
        self.assertEqual(self.history(f"dev:ip:{self.B}")[0], 2)
        self.assertEqual(self.history(f"dev:ip:{self.C}")[0], 2)

    def test_offline_row_with_the_mac_doesnt_block_the_owner(self):
        self.c.execute("INSERT INTO devices (ip, mac, online, last_seen) VALUES (?,?,0,?)",
                       ("192.168.1.99", self.MAC, T0 - 86400))     # long gone
        self.sweep({self.A: self.MAC}, 0)
        self.seed(f"dev:{self.MAC}")
        self.sweep({self.A: self.MAC, self.B: self.MAC}, 1)
        self.assertEqual(self.history(f"dev:ip:{self.A}"), (3, 1))

    def test_pings_written_just_after_the_move_follow_on_the_next_sweep(self):
        self.sweep({self.A: self.MAC}, 0)
        self.seed(f"dev:{self.MAC}")
        self.sweep({self.A: self.MAC, self.B: self.MAC}, 1)
        self.c.execute("INSERT INTO pings VALUES (?,?,5.0)", (T0 + 400, f"dev:{self.MAC}"))  # was queued
        self.sweep({self.A: self.MAC, self.B: self.MAC}, 2)
        self.assertEqual(self.history(f"dev:ip:{self.A}")[0], 4)
        self.assertEqual(self.history(f"dev:{self.MAC}")[0], 0)

    def test_one_missed_sweep_moves_nothing(self):
        # A and B share a MAC; B misses a single sweep. That's within the offline grace, so A
        # stays shared: no id change, no history moved (the review's flap case)
        self.sweep({self.A: self.MAC, self.B: self.MAC}, 0)
        self.seed(f"dev:ip:{self.A}")
        self.sweep({self.A: self.MAC})                         # B missed this one
        self.sweep({self.A: self.MAC, self.B: self.MAC})       # and is back
        self.assertEqual(self.history(f"dev:ip:{self.A}"), (3, 1))
        self.assertEqual(self.history(f"dev:{self.MAC}"), (0, 0))
        self.assertEqual(store.get_state(self.c, "shared_mac_ips"), sorted([self.A, self.B]))

    def test_became_shared_doesnt_merge_into_an_occupied_ip_id(self):
        # the IP's own id still holds an earlier device's history (that address belonged to
        # someone else before): the MAC-keyed history stays where it is
        self.c.execute("INSERT INTO pings VALUES (?,?,7.0)", (T0 - 86400, f"dev:ip:{self.A}"))
        self.sweep({self.A: self.MAC}, 0)
        self.seed(f"dev:{self.MAC}")
        self.sweep({self.A: self.MAC, self.B: self.MAC})
        self.assertEqual(self.history(f"dev:{self.MAC}"), (3, 1))
        self.assertEqual(self.history(f"dev:ip:{self.A}"), (1, 0))

    def test_own_leftovers_dont_block_moving_back(self):
        # moves never delete, so a minute both ids had stays behind; when the device's MAC stops
        # being shared again, those leftovers are its own and mustn't block the move back
        self.sweep({self.A: self.MAC}, 0)
        self.seed(f"dev:{self.MAC}")
        self.sweep({self.A: self.MAC, self.B: self.MAC})        # became shared: history moved to dev:ip:A
        # around the change, the same minute was rolled up under both ids (late pings): the
        # replay on the next sweep can't merge that minute, so it stays behind under the MAC id
        minute = int(T0 // 60 * 60) + 600
        self.c.executemany("INSERT INTO pings_1m (ts, target, n, lost, avg, max) VALUES (?,?,12,0,9.0,9.0)",
                           [(minute, f"dev:{self.MAC}"), (minute, f"dev:ip:{self.A}")])
        self.sweep({self.A: self.MAC, self.B: self.MAC})
        self.assertEqual(self.history(f"dev:{self.MAC}"), (0, 1))  # the leftover
        self.gone_sweeps({self.A: self.MAC})                      # B leaves for good
        self.assertEqual(self.history(f"dev:{self.MAC}")[0], 3)   # A's history came back despite the leftover
        self.assertEqual(self.history(f"dev:ip:{self.A}")[0], 0)

    def test_blocked_move_is_logged_once(self):
        from unittest import mock
        self.c.execute("INSERT INTO pings VALUES (?,?,7.0)", (T0 - 86400, f"dev:ip:{self.A}"))  # someone else's
        self.sweep({self.A: self.MAC}, 0)
        self.seed(f"dev:{self.MAC}")
        with mock.patch.object(collectors, "log") as log, mock.patch.object(collectors, "_blocked_moves_logged", set()):
            self.sweep({self.A: self.MAC, self.B: self.MAC})
            self.sweep({self.A: self.MAC})                        # B blips; still shared
            self.sweep({self.A: self.MAC, self.B: self.MAC})
        lines = [c.args[0] for c in log.call_args_list if "already holds another device's history" in c.args[0]]
        self.assertEqual(len(lines), 1)
        self.assertIn(f"dev:{self.MAC}", lines[0])

    def test_ownership_records_are_bounded(self):
        from unittest import mock
        with mock.patch.object(collectors, "ID_OWNERS_MAX", 4):
            for i in range(10):                                  # ten devices each gain and lose a sharer
                a, b, mac = f"10.0.{i}.1", f"10.0.{i}.2", f"aa:bb:cc:00:01:{i:02x}"
                self.sweep({a: mac})
                self.c.execute("INSERT INTO pings VALUES (?,?,5.0)", (T0, f"dev:{mac}"))
                self.sweep({a: mac, b: mac})
            self.assertLessEqual(len(store.get_state(self.c, collectors.ID_OWNERS_KEY, {})), 4)

    def test_stale_ownership_record_is_dropped_and_approves_nothing(self):
        # a record for an id that holds nothing any more, from a move long ago, is pruned; it
        # must not let a later device merge into that id once something else is stored there
        old = int(T0) - 2 * collectors.ID_OWNER_GRACE_S
        store.set_state(self.c, collectors.ID_OWNERS_KEY, {f"dev:ip:{self.A}": [self.A, self.MAC, old]})
        self.sweep({self.A: self.MAC}, 0)
        self.assertEqual(store.get_state(self.c, collectors.ID_OWNERS_KEY, {}), {})

    def test_recent_record_for_an_empty_id_is_kept_through_the_grace(self):
        # right after a move the old id holds nothing; its record must survive until late rows
        # could arrive, and go once the grace has passed (all on the sweep's clock)
        tid = f"dev:{self.MAC}"
        store.set_state(self.c, collectors.ID_OWNERS_KEY, {tid: [self.A, self.MAC, T0]})
        self.sweep({self.A: self.MAC}, 0)                                   # at T0: just made
        self.assertIn(tid, store.get_state(self.c, collectors.ID_OWNERS_KEY, {}))
        grace_sweeps = int(collectors.ID_OWNER_GRACE_S // SWEEP)
        self.sweep({self.A: self.MAC}, grace_sweeps - 1)                    # still within the grace
        self.assertIn(tid, store.get_state(self.c, collectors.ID_OWNERS_KEY, {}))
        self.sweep({self.A: self.MAC}, grace_sweeps + 1)                    # past it
        self.assertNotIn(tid, store.get_state(self.c, collectors.ID_OWNERS_KEY, {}))

    def test_record_from_the_future_isnt_recent(self):
        tid = f"dev:{self.MAC}"
        store.set_state(self.c, collectors.ID_OWNERS_KEY, {tid: [self.A, self.MAC, T0 + 86400]})  # clock stepped back
        self.sweep({self.A: self.MAC}, 0)
        self.assertNotIn(tid, store.get_state(self.c, collectors.ID_OWNERS_KEY, {}))

    def test_blocked_move_log_memory_is_bounded(self):
        from unittest import mock
        with mock.patch.object(collectors, "_BLOCKED_LOG_MAX", 3), \
                mock.patch.object(collectors, "_blocked_moves_logged", set()) as logged, \
                mock.patch.object(collectors, "log"):
            for i in range(10):
                a, b, mac = f"10.1.{i}.1", f"10.1.{i}.2", f"aa:bb:cc:00:02:{i:02x}"
                self.c.execute("INSERT INTO pings VALUES (?,?,7.0)", (T0 - 86400, f"dev:ip:{a}"))  # occupied
                self.sweep({a: mac})
                self.c.execute("INSERT INTO pings VALUES (?,?,5.0)", (T0, f"dev:{mac}"))
                self.sweep({a: mac, b: mac})                     # blocked each time
            self.assertLessEqual(len(logged), 3)

    def test_sharing_counts_devices_still_within_the_grace(self):
        self.assertEqual(collectors.shared_mac_ips({self.A}, {self.A: self.MAC}, {self.B: self.MAC.upper()}),
                         {self.A, self.B})
        self.assertEqual(collectors.shared_mac_ips({self.A}, {self.A: self.MAC}, {}), set())

    def test_mac_id_holding_someone_elses_history_is_not_merged_into(self):
        # the MAC id still holds an earlier owner's history: the device now alone on the MAC
        # keeps its own id rather than being merged into that
        self.sweep({self.A: self.MAC, self.B: self.MAC}, 0)
        self.seed(f"dev:ip:{self.A}")
        self.c.execute("INSERT INTO pings VALUES (?,?,7.0)", (T0 - 3600, f"dev:{self.MAC}"))
        self.c.execute(f"INSERT INTO labels VALUES ('dev:{self.MAC}', 'Earlier owner')")
        self.sweep({self.A: self.MAC}, 1)
        self.assertEqual(self.history(f"dev:ip:{self.A}"), (3, 1))
        self.assertEqual(self.history(f"dev:{self.MAC}"), (1, 0))
        self.assertEqual(dict(self.c.execute("SELECT key, name FROM labels")),
                         {f"dev:ip:{self.A}": "Lounge PC", f"dev:{self.MAC}": "Earlier owner"})

    def test_a_move_never_deletes_anything(self):
        old, new, minute = "dev:ip:192.168.1.10", "dev:aa:bb:cc:00:00:01", int(T0 // 60 * 60)
        self.c.executemany("INSERT INTO pings_1m (ts, target, n, lost, avg, max) VALUES (?,?,12,0,?,?)", [(minute, old, 5.0, 5.0), (minute, new, 9.0, 9.0),
                                                                         (minute + 60, old, 6.0, 6.0)])
        self.c.executemany("INSERT INTO labels VALUES (?,?)", [(old, "Old name"), (new, "New name")])
        store.move_device_history(self.c, old, new)
        self.assertEqual(self.c.execute("SELECT COUNT(*) FROM pings_1m").fetchone()[0], 3)  # none deleted
        self.assertEqual(sorted(self.c.execute("SELECT target, ts FROM pings_1m")),
                         sorted([(old, minute), (new, minute), (new, minute + 60)]))
        self.assertEqual(dict(self.c.execute("SELECT key, name FROM labels")), {old: "Old name", new: "New name"})


class DeviceStateTest(unittest.TestCase):
    def test_states(self):
        self.assertEqual(device_state(0, 100, 500), STATE_OFFLINE)
        self.assertEqual(device_state(1, 100, 500), STATE_ASLEEP)    # last answer before the cutoff
        self.assertEqual(device_state(1, 600, 500), STATE_ONLINE)
        self.assertEqual(device_state(1, None, 500), STATE_ONLINE)   # never answers ping: just online
        self.assertEqual(device_state(1, 100, None), STATE_ONLINE)   # not enough sweeps to judge
        # #122: never answers ping and the router calls it offline - a sleeping card answering ARP
        self.assertEqual(device_state(1, None, 500, True), STATE_ASLEEP)
        self.assertEqual(device_state(1, 600, 500, True), STATE_ONLINE)   # its own recent answer wins
        self.assertEqual(device_state(0, None, 500, True), STATE_OFFLINE)

    def test_the_router_counts_only_while_its_list_is_fresh(self):
        c = mem_db()
        self.addCleanup(c.close)
        store.save_router_clients(c, T0, [{"mac": "AA:00:00:00:00:01", "ip": "x", "name": None, "online": False},
                                          {"mac": "aa:00:00:00:00:02", "ip": "y", "name": None, "online": True}])
        self.assertEqual(router_offline(c, T0 + 60), {"aa:00:00:00:00:01"})
        self.assertEqual(router_offline(c, T0 + ROUTER_FRESH_S + 1), set())   # the router stopped being read


class NameSuffixTest(unittest.TestCase):
    def test_a_device_s_own_older_addresses_are_no_clash(self):
        c = mem_db()
        self.addCleanup(c.close)
        rows = [("192.168.1.109", "a8:7e:ea:00:00:01", "WorkLaptop.lan", 1), ("192.168.1.164", "a8:7e:ea:00:00:01", "WorkLaptop.lan", 0),
                ("192.168.1.161", "52:49:a1:00:00:01", "mac.lan", 1), ("192.168.1.181", "1c:f6:4c:00:00:01", "mac.lan", 1)]
        c.executemany("INSERT INTO devices (ip, mac, name, first_seen, last_seen, online) VALUES (?,?,?,0,0,?)", rows)
        c.execute("UPDATE devices SET friendly='Mac mini' WHERE name='mac.lan'")
        c.execute("UPDATE devices SET friendly='WorkLaptop' WHERE name='WorkLaptop.lan'")
        names = {r[1]: r[8] for r in device_rows(c)}
        self.assertEqual(names["192.168.1.109"], "WorkLaptop")                      # one device, two addresses
        self.assertEqual(names["192.168.1.161"], "Mac mini · 192.168.1.161")       # two devices, one name
        self.assertEqual(names["192.168.1.181"], "Mac mini · 192.168.1.181")


if __name__ == "__main__":
    unittest.main()
