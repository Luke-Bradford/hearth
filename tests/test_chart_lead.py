"""#71: a dozing device (a phone asleep) never stands in for its group on the latency and loss
charts - its dropped pings aren't the network's."""
import unittest

from hearth import analysis


def st(loss, p50, responding=True):
    return {"loss_pct": loss, "p50": p50, "responding": responding}


class RepresentativeTest(unittest.TestCase):
    def test_the_steadiest_member_but_never_a_dozing_one(self):
        stats = {"phone": st(0, 5), "unit": st(1, 12), "laptop": st(1, 20)}
        self.assertEqual(analysis._representative(["phone", "unit", "laptop"], stats), "phone")
        self.assertEqual(analysis._representative(["phone", "unit", "laptop"], stats, dozing={"phone"}), "unit")

    def test_a_group_of_only_dozing_devices_gets_no_line(self):
        stats = {"phone": st(40, 50), "watch": st(60, 80)}
        self.assertIsNone(analysis._representative(["phone", "watch"], stats, dozing={"phone", "watch"}))

    def test_silent_members_are_skipped_as_before(self):
        stats = {"a": st(0, 5, responding=False), "b": st(2, 9)}
        self.assertEqual(analysis._representative(["a", "b"], stats), "b")


class PortableTest(unittest.TestCase):
    def test_the_mesh_names_the_devices_that_sleep(self):
        from hearth import mesh, store
        from tests.test_router_usage import mem_db
        c = mem_db()
        self.addCleanup(c.close)
        store.set_state(c, mesh.MESH_STATE_KEY, {"clients": [
            {"mac": "fa:6b:bd:5e:00:09", "kind": "phone"}, {"mac": "aa:aa:aa:aa:aa:aa", "kind": "pc"},
            {"mac": "bb:bb:bb:bb:bb:bb", "kind": "tablet"}, {"mac": "cc:cc:cc:cc:cc:cc"}, "junk"]})
        self.assertEqual(analysis.portable_devices(c), {"dev:fa:6b:bd:5e:00:09", "dev:bb:bb:bb:bb:bb:bb"})
        store.set_state(c, mesh.MESH_STATE_KEY, ["not", "a", "reading"])
        self.assertEqual(analysis.portable_devices(c), set())


if __name__ == "__main__":
    unittest.main()
