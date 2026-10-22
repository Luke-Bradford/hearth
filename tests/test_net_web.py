import http.client
import json
import re
import socket
import subprocess
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from unittest import mock

import hearth.main
from hearth import analysis, net, store
from hearth.main import supervise
from hearth.web import _LABEL_KEY, MAX_MINUTES, Handler, host_allowed, parse_minutes, same_origin, snap
from tests.helpers import JS_DOM, js_defs, mem_db, needs_node, page_code, run_js, strip_comments


class HostAllowedTest(unittest.TestCase):
    def test_ip_literals_and_own_names(self):
        me = socket.gethostname().split(".")[0]
        for h in ("192.168.1.60:8080", "192.168.1.60", "[::1]:8080", "localhost:8080",
                  f"{me}:8080", f"{me.lower()}.local:8080"):
            self.assertTrue(host_allowed(h), h)

    def test_rebinding_domains_refused(self):
        for h in ("evil.example:8080", "evil.example", "192.168.1.60.nip.io:8080", "", None):
            self.assertFalse(host_allowed(h), h)


class SnapTest(unittest.TestCase):
    def test_snaps_up_to_a_fixed_window(self):
        self.assertEqual(snap(60), 60)
        self.assertEqual(snap(61), 180)
        self.assertEqual(snap(1), 5)
        self.assertEqual(snap(5000, 1440), 1440)
        self.assertEqual(snap(MAX_MINUTES), MAX_MINUTES)


def call_args(body, name):
    """The argument text of every `.name(...)` call in body, matching nested brackets."""
    out, i = [], 0
    while (i := body.find(f".{name}(", i)) != -1:
        j, depth = i + len(name) + 2, 1
        while depth and j < len(body):
            depth += {"(": 1, ")": -1}.get(body[j], 0)
            j += 1
        out.append(body[i + len(name) + 2:j - 1])
        i = j
    return out


class DashboardFocusTest(unittest.TestCase):
    def test_redraws_restore_focus_without_scrolling(self):
        # the map and the traffic picker are redrawn every refresh; a plain focus() scrolls the
        # page back up to them (#29)
        page = page_code()
        for start, end in (("function renderMap(", "function renderDetail("),
                           ("function renderTrafficCharts(", "\n}\n")):
            s = page.index(start)
            body = page[s:page.index(end, s)]
            calls = call_args(body, "focus")
            self.assertTrue(calls, start)
            for args in calls:
                self.assertRegex(args, r"preventScroll\s*:\s*true", start)

    def test_call_args_handles_nested_brackets(self):
        self.assertEqual(call_args("x.focus(f(a), {preventScroll:true}); y.focus()", "focus"),
                         ["f(a), {preventScroll:true}", ""])

    def test_comments_are_ignored(self):
        self.assertNotIn("comment-only", strip_comments("a // comment-only\n"))
        self.assertNotIn("block-only", strip_comments("a /* block-only\n */ b"))
        self.assertIn('"http://x"', strip_comments('u="http://x"'))


class DashboardTrafficTest(unittest.TestCase):
    def test_download_and_upload_are_separate_filterable_charts(self):
        # one chart each, no upload drawn below zero, and the device filter replaces the legend (#31)
        page = page_code()
        start = page.index("function renderTrafficCharts(")
        body = page[start:page.index("\n}\n", start)]  # to the function's closing brace
        self.assertIn('$("#trafficdown")', body)
        self.assertIn('$("#trafficup")', body)
        self.assertNotIn("-p[2]", body)
        self.assertIn("legend:{display:false}", body)
        self.assertIn("trafficShown", body)


class IncidentsRangeTest(unittest.TestCase):
    def test_long_ranges_reach_the_stored_episodes(self):
        # episodes before the last few hours come from storage now, so /api/incidents isn't
        # capped at a day any more: a 7-day request is computed as 7 days
        srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)   # cleanups run in reverse: shutdown first, then close
        self.addCleanup(srv.shutdown)
        asked = []

        def record(fn, conn, minutes, **kw):   # stands in for the cache: note what was asked for
            asked.append((fn.__name__, minutes))
            return {}
        # store.db: the handler opens a connection per request; an in-memory one keeps the real
        # database out of the test (the mocked cache never uses it)
        with mock.patch.object(store, "db", side_effect=mem_db), mock.patch.object(analysis, "cached", side_effect=record):
            for minutes in (10080, 43200, MAX_MINUTES):
                c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=5)
                self.addCleanup(c.close)   # closed even when an assertion fails (#71)
                c.request("GET", f"/api/incidents?minutes={minutes}")
                self.assertEqual(c.getresponse().status, 200)
                c.close()
        self.assertEqual(asked, [("incidents", 10080), ("incidents", 43200), ("incidents", MAX_MINUTES)])

    def test_the_largest_window_reads_the_store(self):
        # the top window (400 days) goes through the stored path: an episode from 399 days ago is
        # there, and only the last few hours are built live (incidents_since)
        c = mem_db()
        self.addCleanup(c.close)
        old = int(time.time()) - 399 * 86400
        record = {"start": old, "end": old + 20, "kind": "outage", "level": "bad", "cause": "Internet down",
                  "truncated": False}
        c.execute("INSERT INTO episodes (start, end, kind, level, truncated, data) VALUES (?,?,?,?,?,?)",
                  (old, old + 20, "outage", "bad", 0, json.dumps(record)))
        before = time.time()
        out = analysis.incidents(c, snap(MAX_MINUTES))
        # the live part starts at B, the start of the hour about LIVE_S ago - not 400 days back
        b = int((before - analysis.LIVE_S) // 3600 * 3600)
        self.assertIn(out["incidents_since"], (b, b + 3600))     # an hour boundary may pass mid-test
        self.assertEqual([e["start"] for e in out["episodes"]], [old])


class MinutesTest(unittest.TestCase):
    def test_whole_minutes_in_range(self):
        self.assertEqual(parse_minutes("60"), 60)
        self.assertEqual(parse_minutes(str(MAX_MINUTES)), MAX_MINUTES)

    def test_rejects_non_finite_fractional_and_out_of_range(self):
        for raw in ("nan", "inf", "-inf", "60.0001", "0", "-5", str(MAX_MINUTES + 1), "", "abc"):
            self.assertIsNone(parse_minutes(raw), raw)


class SameOriginTest(unittest.TestCase):
    def test_non_browser_clients_have_no_origin(self):
        self.assertTrue(same_origin(None, "192.168.1.60:8080"))

    def test_dashboard_on_same_host(self):
        self.assertTrue(same_origin("http://192.168.1.60:8080", "192.168.1.60:8080"))

    def test_other_sites_refused(self):
        self.assertFalse(same_origin("https://evil.example", "192.168.1.60:8080"))
        self.assertFalse(same_origin("http://192.168.1.60:9999", "192.168.1.60:8080"))
        self.assertFalse(same_origin("http://192.168.1.60:8080", None))


class CacheTest(unittest.TestCase):
    def test_cache_is_size_capped(self):
        analysis.clear_cache()
        for m in range(1, analysis._CACHE_MAX * 3):
            analysis.cached(lambda conn, minutes: minutes, None, m)
        self.assertLessEqual(len(analysis._cache), analysis._CACHE_MAX)
        analysis.clear_cache()


class SuperviseTest(unittest.TestCase):
    def test_restarts_a_crashing_job(self):
        stop, calls = threading.Event(), []

        def job():
            calls.append(1)
            if len(calls) < 3:
                raise RuntimeError("boom")
            stop.set()

        delay, hearth.main.RESTART_DELAY_S = hearth.main.RESTART_DELAY_S, 0
        try:
            supervise("test", job, (), stop)
        finally:
            hearth.main.RESTART_DELAY_S = delay
        self.assertEqual(len(calls), 3)


class RadioOwnerTest(unittest.TestCase):
    def test_access_point_bssid_maps_to_its_device(self):
        macs = ["bc:f8:7e:5e:00:0c", "3c:58:36:5e:00:0d", "1c:f6:4c:5e:00:01"]
        self.assertEqual(net.radio_owner("a2:f8:7e:5e:00:0e", macs), "bc:f8:7e:5e:00:0c")
        self.assertEqual(net.radio_owner("c6:58:36:5e:00:0f", macs), "3c:58:36:5e:00:0d")

    def test_neighbour_radio_has_no_owner(self):
        self.assertIsNone(net.radio_owner("00:11:22:5e:00:10", ["bc:f8:7e:5e:00:0c"]))


class PrivateMacTest(unittest.TestCase):
    def test_locally_administered_bit(self):
        self.assertTrue(net.is_private_mac("a6:f4:15:5e:00:11"))
        self.assertFalse(net.is_private_mac("1c:f6:4c:5e:00:01"))


class LabelKeyTest(unittest.TestCase):
    def test_accepts_known_key_shapes(self):
        for k in ("grp:12", "dev:1c:f6:4c:5e:00:01", "dev:ip:192.168.1.20"):
            self.assertTrue(_LABEL_KEY.match(k), k)

    def test_rejects_anything_else(self):
        for k in ("grp:", "grp:1;DROP TABLE labels", "dev:zz:zz:zz:zz:zz:zz", "labels", "dev:ip:1.2.3", ""):
            self.assertFalse(_LABEL_KEY.match(k), k)


class DashboardEpisodesTest(unittest.TestCase):
    def test_header_table_and_tile_use_episodes(self):
        page = page_code()
        status = page[page.index("function renderStatus("):page.index("\n}\n", page.index("function renderStatus("))]
        self.assertIn("Slowdowns &amp; outages (last hour)", page)   # the header cell, on every tab
        self.assertIn("st.episodes_1h", status)                      # episodes, from /api/status
        self.assertIn("st.episodes_level_1h", status)
        self.assertNotIn("incidents_1h", status)
        table = page[page.index("function renderIncidents("):page.index("\n}\n", page.index("function renderIncidents("))]
        self.assertIn("inc.episodes", table)
        self.assertIn("Show momentary spikes", page)
        self.assertIn("spikes_usual_per_hour", page)
        self.assertNotIn("Lag incidents", page)             # the old heading is gone everywhere


# the client-side judging the page must not do any more (shared by the two tests below)
OLD_JUDGE = r"(?<![\w.])health\("                                        # the old health(), not router_health(
NUMBER_TO_COLOUR = r"[<>]=?\s*-?\d+(\.\d+)?\s*\?\s*\"(bad|warn|good|ok)\""  # x>80?"bad"
MEASURE_VS_NUMBER = r"(p95|p50|loss_pct|spikes|util|rssi|temp_c)(\s*\|\|\s*-?\d+)?\s*\)?\s*[<>]=?\s*-?\d"  # p95>80, (x.util||0)>=60
COLOUR_WORD = r"\"(good|warn|bad|nodata)\""
NUMBER_TO_TAG = r"[<>]=?\s*-?[\d.*]+\s*\?[^:]{0,30}\btag (warn|bad|good)\b"  # x>2**30?"tag warn"


class DashboardLevelsTest(unittest.TestCase):
    def test_no_client_side_thresholds(self):
        page = page_code()
        for pattern in (OLD_JUDGE, NUMBER_TO_COLOUR, MEASURE_VS_NUMBER, NUMBER_TO_TAG):
            self.assertIsNone(re.search(pattern, page), pattern)

    def test_colour_words_only_come_from_the_level_map(self):
        # a quoted colour word may appear only in the LV map, or compared with a level the
        # server sent (`.level==="bad"`); anywhere else it would be the page judging again
        script = "\n".join(re.findall(r"<script(?![^>]*src)[^>]*>(.*?)</script>", page_code(), re.S))
        for line in script.split("\n"):
            if re.search(COLOUR_WORD, line) and not re.match(r"\s*const\s+LV\s*=", line):
                rest = re.sub(r"level\s*===?\s*" + COLOUR_WORD, "", line)
                self.assertIsNone(re.search(COLOUR_WORD, rest), line.strip()[:120])

    def test_threshold_checks_catch_the_old_rules(self):
        # the checks above must actually fire on what they forbid
        old_health = 'function health(h){ if((h.loss_pct||0)>2||h.p95>80) return "bad"; }'
        old_busy = 'const busy=v=>v==null?"":v>=60?"bad":v>=40?"warn":"good";'
        self.assertIsNotNone(re.search(OLD_JUDGE, old_health))
        self.assertIsNotNone(re.search(NUMBER_TO_COLOUR, old_busy))
        self.assertIsNotNone(re.search(MEASURE_VS_NUMBER, old_health))
        self.assertIsNotNone(re.search(MEASURE_VS_NUMBER, "if((w.util||0)<=30)"))
        # the host table's old rules (the review found them hiding in template strings)
        self.assertIsNotNone(re.search(NUMBER_TO_TAG, '<span class="${p.change>2**30?"tag warn":""}">'))
        self.assertIsNotNone(re.search(NUMBER_TO_TAG, '${p.max_handles>=200000?`<span class="tag bad">'))
        self.assertIsNotNone(re.search(MEASURE_VS_NUMBER, "(h.loss_pct||0)>2"))
        self.assertIsNone(re.search(MEASURE_VS_NUMBER, "const util=fmt(x)"))     # no comparison: fine

    def test_header_shows_the_verdict(self):
        page = page_code()
        status = page[page.index("function renderStatus("):page.index("\n}\n", page.index("function renderStatus("))]
        self.assertIn("verdict", status)


class DashboardHistoryTest(unittest.TestCase):
    def incidents(self):
        page = page_code()
        return page[page.index("function renderIncidents("):page.index("function renderDevices(")]

    def test_truncated_start_and_history_notes(self):
        r = self.incidents()
        self.assertIn('e.truncated?"before ":""', r)
        self.assertIn("inc.history_complete===false", r)
        self.assertIn("inc.incidents_since", r)
        self.assertIn(".textContent=", r)       # server text set as text, never as HTML


class DashboardTabsTest(unittest.TestCase):
    """Step 3, part 1: tabs, the address, and fetching only what a tab shows."""

    ENDPOINTS = {"kpi", "overview", "summary", "series", "incidents", "devices", "events", "wifi", "usage", "mesh", "host",
                 "dns", "settings", "speedtest", "digest", "quality", "setup", "security"}

    def tab_fetch(self):
        page = page_code()
        block = page[page.index("const TAB_FETCH="):page.index("};", page.index("const TAB_FETCH="))]
        return {t: set(re.findall(r'"(\w+)"', eps)) for t, eps in re.findall(r"(\w+):\[([^\]]*)\]", block)}

    def test_every_tab_has_a_panel_and_a_fetch_list(self):
        page = page_code()
        block = page[page.index("const TABS="):page.index(";", page.index("const TABS="))]
        tabs = re.findall(r'\["(\w+)","[\w ]+"\]', block)
        self.assertEqual(tabs, ["overview", "network", "devices", "history", "usage", "system"])
        for t in tabs:
            self.assertIn(f'id="tab-{t}"', page)
        self.assertEqual(set(self.tab_fetch()), set(tabs))

    def test_every_endpoint_is_fetched_by_some_tab_and_only_known_ones(self):
        fetched = set().union(*self.tab_fetch().values())
        self.assertEqual(fetched, self.ENDPOINTS)
        self.assertNotIn("incidents", self.tab_fetch()["overview"])     # Overview stays light
        self.assertEqual(self.tab_fetch()["usage"], {"usage", "speedtest"})

    def test_refresh_fetches_only_the_shown_tab(self):
        page = page_code()
        refresh = page[page.index("async function refresh("):page.index("\n}\n", page.index("async function refresh("))]
        self.assertIn('["status",...TAB_FETCH[shown]]', refresh)
        self.assertNotIn('get("/api/series")', refresh)                 # no fixed list any more

    @needs_node
    def test_address_is_checked_and_parsed_safely(self):
        code = JS_DOM + js_defs("const RANGES=", "const TABS=", "const ITEM_RE=", "const validItem=", "function readHash(")
        hashes = ["#/history?range=7d&at=1792440000&item=ep:1792440000", "", "#/nope?range=2w", "#/system",
                  "#/devices?item=dev:aa:bb&at=12", "#/overview?item=src:constructor()", "#/network?item=alerts&range=1y",
                  "#history?range=1h", "#/usage?item=" + "dev:" + "x" * 200]
        out = run_js(code + f"const hs={json.dumps(hashes)};", "hs.map(h=>{location.hash=h;return readHash()})")
        self.assertEqual(out, [
            {"tab": "history", "range": "7d", "at": 1792440000, "item": "ep:1792440000"},
            {"tab": "overview", "range": None, "at": None, "item": None},
            {"tab": "overview", "range": None, "at": None, "item": None},     # unknown tab and range: fall back
            {"tab": "system", "range": None, "at": None, "item": None},       # no query at all
            {"tab": "devices", "range": None, "at": None, "item": "dev:aa:bb"},   # a too-short moment dropped
            {"tab": "overview", "range": None, "at": None, "item": None},     # not a known kind
            {"tab": "network", "range": "1y", "at": None, "item": "alerts"},
            {"tab": "history", "range": "1h", "at": None, "item": None},      # "#history" without the slash
            {"tab": "usage", "range": None, "at": None, "item": None}])       # over ITEM_MAX
        page = page_code()
        self.assertIn("history.pushState", page)
        self.assertIn('addEventListener("hashchange"', page)   # Back, and links that change the address

    def test_ranges_reach_a_year(self):
        page = page_code()
        self.assertIn('["1y",525600]', page)
        from hearth.web import WINDOWS, snap
        self.assertIn(525600, WINDOWS)
        self.assertEqual(snap(525600), 525600)                            # computed as 365 days, not 400

    def test_tabs_are_keyboard_reachable(self):
        page = page_code()
        self.assertIn('role="tablist"', page)
        self.assertIn('role="tab"', page)
        self.assertIn("ArrowRight", page)


class DashboardOverviewTest(unittest.TestCase):
    """Step 3, part 2: the Overview draws what /api/overview and /api/kpi decide."""

    def overview(self):
        page = page_code()
        return page[page.index("function renderOverview("):page.index("\n}\n", page.index("function renderOverview("))]

    def test_server_text_is_escaped(self):
        o = self.overview()
        self.assertIn("esc(v.text)", o)
        self.assertIn("esc(i.text)", o)
        self.assertIn("esc(what)", o)
        self.assertIn("o.timeline_error", o)
        self.assertNotIn("esc(s.level)", o)                 # escaped once, as part of the label

    def test_a_failing_overview_says_so_and_never_claims_nothing_needs_attention(self):
        page = page_code()
        self.assertIn("overview:null", page[page.index("const FALLBACK="):page.index("\n", page.index("const FALLBACK="))])
        o = self.overview()
        self.assertIn("Hearth couldn't load this list.", o)
        self.assertIn("Hearth couldn't load the last 24 hours.", o)

    def test_timeline_blocks_are_labelled_buttons_that_open_history_at_that_moment(self):
        o = self.overview()
        self.assertIn("<button", o)
        self.assertIn('aria-label="${esc(what)}"', o)
        self.assertIn('go({tab:"history",range:"24h",at:+b.dataset.at})', o)

    def test_tiles_and_attention_link_to_known_tabs_only(self):
        page = page_code()
        self.assertEqual(page.count('class="livefig tile" data-tab='), 6)   # +Calls (step 4.3b)
        self.assertIn('tabName(i.tab)?i.tab:"overview"', self.overview())

    def test_at_is_checked_against_the_servers_clock_and_never_sent(self):
        page = page_code()
        self.assertIn("lastStatus?.updated", page[page.index("const atShown="):page.index("\n", page.index("const atShown="))])
        get = page[page.index("const get="):page.index("\n", page.index("const get="))]
        self.assertNotRegex(get, r"\bat\b")                # the fetch helper never carries `at`
        self.assertIn(r"/^\d{9,11}$/", page)


class DashboardDevicesFilterTest(unittest.TestCase):
    """Step 3, part 3a: search and filters on the Devices tab."""

    def test_inputs_are_labelled_and_the_unit_list_is_escaped(self):
        page = page_code()
        for el in ("devq", "devstate", "devlink", "devunit"):
            self.assertRegex(page, rf'id="{el}"[^>]*aria-label="')
        self.assertIn('<option value="${esc(u)}">${esc(u)}</option>', page)

    def test_both_layouts_say_which_unit_and_link(self):
        page = page_code()
        self.assertIn("return {root,areaOf,unitOf,linkOf,fromMesh:true};", page)
        self.assertIn("return {root,areaOf,unitOf:areaOf,linkOf:{}};", page)

    def test_filters_stay_in_the_page(self):
        page = page_code()
        get = page[page.index("const get="):page.index("\n", page.index("const get="))]
        self.assertNotIn("devFilter", get)
        self.assertEqual(page.count("devFilter()"), 1)          # read only where the table is drawn

    @needs_node
    def test_matching(self):
        page = page_code()
        fn = page[page.index("function devMatches("):page.index("\n}\n", page.index("function devMatches(")) + 2]
        dev = {"id": "dev:aa:bb", "name": "Kitchen iPad", "info": {"ip": "192.168.1.40", "vendor": "Apple", "online": True},
               "area": "Office · 5 GHz", "unit": "Office", "link": "wifi", "me": False}
        off = {**dev, "info": {**dev["info"], "online": False}}
        timing = {**dev, "link": None}
        cases = [(dev, {}), (dev, {"q": "ipad"}), (dev, {"q": "192.168.1.4"}), (dev, {"q": "apple"}), (dev, {"q": "aa:bb"}),
                 (dev, {"q": "office"}), (dev, {"q": "tv"}), (dev, {"state": "on"}), (dev, {"state": "off"}),
                 (off, {"state": "off"}), ({**off, "me": True}, {"state": "on"}), (dev, {"link": "wifi"}),
                 (dev, {"link": "wired"}), (timing, {"link": "wifi"}), (timing, {}), (dev, {"unit": "Office"}),
                 (dev, {"unit": "Bedroom"}), (dev, {"q": "ipad", "unit": "Bedroom"})]
        script = fn + "\nconst cases=" + json.dumps(cases) + ";\nconsole.log(JSON.stringify(cases.map(([d,f])=>devMatches(d,{q:'',state:'',link:'',unit:'',...f}))));"
        out = subprocess.run(["node", "-e", script], capture_output=True, text=True, timeout=30, check=True).stdout
        self.assertEqual(json.loads(out), [True, True, True, True, True, True, False, True, False,
                                           True, True, True, False, False, True, True, False, False])


class DashboardSidePanelTest(unittest.TestCase):
    """Step 3, part 3b: the side panel, opened by item= in the address."""

    def fn(self, start, end="\n}\n"):
        page = page_code()
        return page[page.index(start):page.index(end, page.index(start)) + len(end)]

    def test_the_panel_is_a_labelled_dialog_with_a_close_button(self):
        page = page_code()
        self.assertIn('<dialog id="panel" aria-labelledby="panel-title">', page)
        self.assertIn('id="panel-close" type="button" aria-label="Close"', page)
        self.assertNotIn('class="mapwrap"', page)                      # the fixed pane is gone
        self.assertNotIn("hearth_selected", page)                      # the address is the truth now

    def test_modal_on_a_phone_docked_otherwise(self):
        self.assertIn("narrowScreen()?dlg.showModal():dlg.show()", self.fn("function renderPanel("))

    def test_an_item_whose_data_is_missing_is_kept_and_one_not_found_is_dropped_with_a_note(self):
        p = self.fn("function renderPanel(")
        self.assertIn("if(item&&(!data||failed))", p)                            # loading or failed: kept
        self.assertIn("Couldn't load this item", p)
        self.assertIn("history.replaceState(null,\"\",hashFor(tab,rangeLabel(),at,null))", p)   # not found: dropped
        self.assertIn("esc(panelNote)", p)

    def test_the_panel_fetches_the_map_data_and_a_failure_only_affects_the_panel(self):
        r = self.fn("async function refresh(")
        self.assertIn('extra=item&&kind==="map"?MAP_DATA.filter(n=>!own.includes(n)):[]', r)
        self.assertIn("return PANEL_FAILED", r)
        self.assertIn("renderPanel(panelFailed?null:{tree:tree??undefined,eps:epData?.episodes,sources:d.status?.sources,alerts:alertsData},panelFailed)", r)

    def test_a_fallback_never_makes_a_valid_item_look_missing(self):
        # #83 review: usage and mesh fall back to {available:false}; for the panel that is a failure
        r = self.fn("async function refresh(")
        fetch_one = r[r.index("const fetchOne="):r.index("let got;")]
        self.assertLess(fetch_one.index("mapFailed=true"), fetch_one.index("return FALLBACK[n]"))
        self.assertIn('(item?.startsWith("unit:")&&d.mesh&&!d.mesh.available)', r)
        # the tab still draws from its fallbacks: only the panel sees the failure
        self.assertIn("[d.summary,d.devices,d.usage,d.mesh].every(x=>x&&x!==PANEL_FAILED)", r)

    def test_links_carry_the_item_and_server_items_are_checked(self):
        page = page_code()
        self.assertIn('href="${esc(hashFor("devices",rangeLabel(),null,id))}"', page)
        self.assertIn("validItem(i.item)?i.item:null", page)       # the server's items: same check, length included
        self.assertIn("item:validItem(it)?it:null", page)

    def test_focus_returns_to_the_opener_recorded_at_click(self):
        page = page_code()
        self.assertIn('const a=e.target.closest?.("a.itemlink"); if(a) panelOpener=a', page)
        self.assertIn("panelOpener=g; go({item:keyItem(g.dataset.key)})", page)
        close = self.fn("function closePanel(")
        self.assertLess(close.index("opener=panelOpener"), close.index("go({item:null})"))

    def test_only_a_device_reaches_the_server(self):
        # the one request built from an item: a device's places, for a device found in loaded data
        page = page_code()
        self.assertEqual(page.count("/api/device/places?id="), 1)
        self.assertIn('placesHtml(n.id,tree):null', page)
        self.assertIn('n.id?.startsWith("dev:")', page)

    @needs_node
    def test_item_parsing(self):
        page = page_code()
        consts = page[page.index("const ITEM_RE="):page.index("let at=null")]
        script = (consts + "\nconst ok=validItem;"
                  "\nconsole.log(JSON.stringify([ok('dev:aa:bb'),ok('unit:aa'),ok('router'),ok('area:Office'),"
                  "ok('ep:123'),ok('javascript:x'),ok('dev:'),ok('dev:'+'a'.repeat(200)),ok(null),ok(42),"
                  "ok('ep:1792486025'),ok('ep:1792486025.5'),ok('src:router'),ok('src:Router'),ok('src:a b'),"
                  "itemKey('unit:aa:bb'),keyItem('mesh:aa:bb'),keyItem('router'),"
                  "itemKind('ep:1792486025'),itemKind('src:mesh'),itemKind('dev:aa'),itemKind(null)]));")
        out = subprocess.run(["node", "-e", script], capture_output=True, text=True, timeout=30, check=True).stdout
        self.assertEqual(json.loads(out), [True, True, True, True, False, False, False, False, False, False,
                                           True, False, True, False, False,
                                           "mesh:aa:bb", "unit:aa:bb", "router", "ep", "src", "map", "map"])

    def test_episodes_and_sources_open_from_their_rows_and_are_escaped(self):
        page = page_code()
        self.assertIn('data-key="ep:${Math.trunc(e.start)}" href="${esc(hashFor("history",rangeLabel(),at,"ep:"+Math.trunc(e.start)))}"', page)
        self.assertIn('validItem("src:"+k)?', page)
        ep = self.fn("function renderEpisode(")
        for s in ("esc(e.cause)", "esc(c)", "LV[e.level]", "esc(span(e.duration_s))"):
            self.assertIn(s, ep)
        self.assertIn("esc(sourceWhy(s))", self.fn("function renderSource("))

    @needs_node
    def test_names_from_the_address_never_reach_the_prototype(self):
        # #84 review: src:constructor must be "not found", not Object.prototype.constructor
        page = page_code()
        own = page[page.index("const ownProp=(o,k)=>"):page.index("\n", page.index("const ownProp=(o,k)=>"))]
        script = own + "\nconsole.log(JSON.stringify([ownProp({router:1},'router'),ownProp({},'constructor')===undefined,ownProp({},'toString')===undefined,ownProp(undefined,'x')===undefined]));"
        out = subprocess.run(["node", "-e", script], capture_output=True, text=True, timeout=30, check=True).stdout
        self.assertEqual(json.loads(out), [1, True, True, True])
        p = self.fn("function renderPanel(")
        self.assertIn('kind==="src"?ownProp(data,item.slice(4)):ownProp(data.byKey,itemKey(item))', p)
        self.assertIn("ownProp(SOURCE_NAMES,name)", self.fn("function renderSource("))

    def test_an_episode_is_looked_for_over_a_range_that_holds_it(self):
        r = self.fn("async function refresh(")
        self.assertIn("rangeFor(+item.slice(3))[1]", r)
        self.assertIn("shown===\"history\"&&minutes>=epWindow", r)       # reuse the tab's own when it's wide enough
        self.assertIn("fetch(`/api/incidents?minutes=${epWindow}`)", r)   # only a range value reaches the server
        self.assertIn('kind==="ep"?epData===PANEL_FAILED||!epData', r)   # each kind fails on its own data


class DashboardStatusShapesTest(unittest.TestCase):
    """Step 3, part 4b: status by shape, word and colour; the map for screen readers."""

    def test_the_css_words_are_the_scripts_words(self):
        page = page_code()
        js = dict(re.findall(r"\[LV\.(\w+)\]:\"([^\"]+)\"", page[page.index("const LV_WORD="):]))
        lv = dict(re.findall(r"(\w+):\"(\w+)\"", page[page.index("const LV={"):page.index("}", page.index("const LV={"))]))
        css = dict(re.findall(r"\.dot\.(\w+)::before\{content:\"([^\"]+)\"\}", page))
        for level, cls in lv.items():
            self.assertEqual(css.get(cls), js[level], f"{cls}: the dot's word and LV_WORD differ")
        for cls in ("good", "warn", "bad"):
            self.assertIn(f".tag.{cls}::after{{content:\" ({js[next(k for k, v in lv.items() if v == cls)]})\"}}", page)

    def test_each_status_has_its_own_shape(self):
        page = page_code()
        for cls, shape in (("good", "●"), ("warn", "▲"), ("bad", "■")):     # #86: the tags' shapes, with fallback
            self.assertIn(f'.tag.{cls}::before{{content:"{shape} ";content:"{shape} " / "";}}', page)
        self.assertIn(".dot.warn{background:var(--warn);box-shadow:none;border-radius:0;clip-path:polygon(", page)
        self.assertIn(".dot.bad{background:var(--bad);box-shadow:none;border-radius:1px}", page)
        m = page[page.index("function marker("):page.index("\n}\n", page.index("function marker("))]
        self.assertIn("n.health===LV.warn){", m)
        self.assertIn("<polygon", m)
        self.assertIn("n.health===LV.bad){", m)
        self.assertIn("<rect", m)
        self.assertIn('class="mk ring"', m)

    def test_the_map_is_a_group_with_a_list_that_mirrors_it(self):
        page = page_code()
        self.assertIn('<svg id="map" role="group" aria-label="Network map">', page)
        self.assertIn('aria-label="${esc(nodeLabel(n))}"', page)
        self.assertIn('<ul id="maplist" class="maplist sr-only" aria-label="Network as a list">', page)
        self.assertIn('${mapAsList?"":\' tabindex="-1"\'}', page)    # hidden links aren't Tab stops
        self.assertIn('type="button" aria-controls="maplist">Show as list</button>', page)
        self.assertNotIn("maplistbtn\").setAttribute(\"aria-pressed", page)        # #86: a changing label, no pressed state
        self.assertIn("if(ul.dataset.html===html) return;", page)              # #86: unchanged list isn't rebuilt

    @needs_node
    def test_node_labels(self):
        page = page_code()
        part = lambda a, b: page[page.index(a):page.index(b, page.index(a))]
        script = "\n".join([part("const LV={", "\nconst lvl="), part("const KIND_WORD=", "\nfunction renderMap("),
                            "const devCount=n=>n.children.filter(c=>c.kind===\"device\").length;",
                            "const kid={kind:'device'};",
                            "console.log(JSON.stringify(["
                            "nodeLabel({name:'Office',kind:'deco',node:{role:'satellite'},health:'good',children:[kid,kid,kid]}),"
                            "nodeLabel({name:'Bedroom',kind:'deco',node:{role:'main'},health:'warn',children:[kid]}),"
                            "nodeLabel({name:'Phone',kind:'device',health:'bad'}),"
                            "nodeLabel({name:'Old TV',kind:'device',health:'nodata'}),"
                            "nodeLabel({name:'Hearth',kind:'device',health:'self'})]));"])
        out = subprocess.run(["node", "-e", script], capture_output=True, text=True, timeout=30, check=True).stdout
        self.assertEqual(json.loads(out), ["Office, mesh unit, good, 3 devices", "Bedroom, main mesh unit, fair, 1 device",
                                           "Phone, device, poor", "Old TV, device, no data", "Hearth, device, this computer"])


class DashboardPhoneLayoutTest(unittest.TestCase):
    """Step 3, part 4c: on a phone, tables are stacked cards and nothing traps page scrolling."""

    def phone_css(self):
        page = page_code()
        i = page.index("@media(max-width:700px){\n  .scroll{")
        return page[i:page.index("\n}\n", i)]

    def test_tables_become_labelled_cards(self):
        css = self.phone_css()
        self.assertIn(".tabpanel table,.tabpanel tbody,.tabpanel tr,.tabpanel td{display:block", css)
        self.assertIn(".tabpanel td::before{content:attr(data-label)", css)
        self.assertIn(".tabpanel td::before{content:attr(data-label);float:left", css)   # not flex: values stay whole
        self.assertIn(".tabpanel thead{position:absolute;width:1px;height:1px;overflow:hidden", css)   # hidden, still read

    def test_nothing_scrolls_inside_the_page_vertically(self):
        self.assertIn(".scroll{max-height:none!important;overflow:visible}", self.phone_css())   # beats inline max-height
        self.assertIn(".tabpanel td:empty{display:none}", self.phone_css())

    def test_every_table_is_labelled_whenever_it_changes(self):
        page = page_code()
        fn = page[page.index("function labelTables("):page.index("\nlet labelQueued")]
        self.assertIn('col+=+td.getAttribute("colspan")||1', fn)              # spans keep later labels aligned
        self.assertIn('!td.hasAttribute("colspan")', fn)
        self.assertIn(':scope>thead>tr:first-child>th', fn)                    # #87: this table's first header row
        self.assertIn('delete td.dataset.label', fn)                            # #87: no stale label
        self.assertIn('.observe($("main"),{childList:true,subtree:true})', page)   # not attributes: no loop

    def test_the_tab_bar_scrolls_sideways_and_the_panel_is_full_screen(self):
        page = page_code()
        self.assertIn(".tabs{display:flex;gap:2px;padding:0 var(--gap);border-bottom:1px solid var(--line);overflow-x:auto", page)
        self.assertIn("@media(max-width:700px){#panel{width:100vw;border-left:0}}", page)


class DashboardOutagesReportTest(unittest.TestCase):
    """Step 4.1: the outage log and the ISP report card on History."""

    def fn(self, name):
        page = page_code()
        i = page.index(f"function {name}(")
        return page[i:page.index("\n}\n", i)]

    def test_parameters_come_from_fixed_lists_and_are_encoded(self):
        page = page_code()
        self.assertEqual(re.findall(r'<option value="(\d+)"', page[page.index('id="outdays"'):page.index("</select>", page.index('id="outdays"'))]),
                         ["7", "30", "90", "365"])                       # hearth.reports.OUTAGE_DAYS
        r = self.fn("renderReports")
        self.assertIn("get(`/api/outages?days=${encodeURIComponent(days)}`)", r)
        self.assertIn("get(month?`/api/report?month=${encodeURIComponent(month)}`:\"/api/report\")", r)
        self.assertIn('if(r) fillMonths($("#repmonth"),r.this_month);', r)  # #90: the server's month, not the browser's
        fill = self.fn("fillMonths")
        self.assertIn("for(let i=0;i<=13;i++)", fill)                     # hearth.reports.REPORT_MONTHS_BACK
        self.assertIn("sel.dataset.current===current) return;", fill)     # #91: rebuilt when the month moves on
        self.assertIn("if([...sel.options].some(o=>o.value===keep)) sel.value=keep;", fill)   # the choice is kept
        self.assertIn("if(reportsBusy){ reportsAgain=true; return }", r)   # #90: a change mid-fetch isn't lost
        self.assertIn("if(reportsAgain) renderReports()", r)

    def test_server_text_is_escaped_and_outages_open_the_side_panel(self):
        o = self.fn("renderOutages")
        self.assertIn("esc(e.cause||\"\")", o)
        self.assertIn('data-key="ep:${Math.trunc(e.start)}"', o)
        self.assertIn("o.limited?", o)                                     # says when only the newest are listed
        rep = self.fn("renderReport")
        self.assertIn("r.partial?", rep)
        self.assertIn("LV[r.uptime.level]", rep)

    def test_a_failed_load_says_so(self):
        self.assertIn('"couldn\'t load"', self.fn("renderOutages"))
        self.assertIn("Couldn't load the report card.", self.fn("renderReport"))


class DashboardUsageMonthTest(unittest.TestCase):
    """Step 4.2: a usage month on the Usage tab."""

    def fn(self, name):
        page = page_code()
        i = page.index(f"function {name}(")
        return page[i:page.index("\n}\n", i)]

    def test_the_month_comes_from_the_server_and_is_encoded(self):
        r = self.fn("renderUsageMonth")
        self.assertIn("get(month?`/api/usage/month?month=${encodeURIComponent(month)}`:\"/api/usage/month\")", r)
        self.assertIn('if(u) fillMonths($("#usemonth"),u.current);', r)    # #91: the current usage month, one helper
        self.assertIn("if(usageBusy){ usageAgain=true; return }", r)

    def test_server_text_is_escaped_and_states_are_said(self):
        d = self.fn("drawUsageMonth")
        self.assertIn("esc(d.name)", d)
        self.assertIn("Couldn't load this month's usage.", d)
        self.assertIn('$("#usedevs tbody").innerHTML="";', d)             # #91: no other month's data left showing
        self.assertIn("if(key===usageDrawn) return;", d)                   # #91: redrawn only when it changed
        self.assertIn("Hearth has no usage for this month", d)
        self.assertIn('u.source==="wan"', d)


class DashboardDnsTest(unittest.TestCase):
    """Step 4.3a: the DNS panel on System."""

    def test_server_text_is_escaped_and_states_are_said(self):
        page = page_code()
        i = page.index("function renderDns(")
        r = page[i:page.index("\n}\n", i)]
        self.assertIn("esc(r.name)", r)
        self.assertIn("esc(r.resolver)", r)
        self.assertIn("LV[r.level]", r)                      # the server's level, with its shape and word
        self.assertIn("Couldn't load the DNS check.", r)
        self.assertIn("Not checked yet", r)
        self.assertIn('dns:"DNS check"', page)               # a source with a name in the sources table


class DashboardSettingsTest(unittest.TestCase):
    """Step 4.5: the Settings form on System."""

    def test_typing_isnt_wiped_and_errors_are_text(self):
        page = page_code()
        self.assertIn("if(!s||settingsDirty) return;", page)               # a refresh never refills a form being edited
        sub = page[page.index('$("#settings").addEventListener("submit"'):page.index("\n});\n", page.index('$("#settings").addEventListener("submit"'))]
        self.assertIn('st.textContent=`Not saved: ${d.error||"the server refused it"}`', sub)   # text, never innerHTML
        self.assertNotIn("innerHTML", sub)
        self.assertIn('/^[0-9]+$/.test(day)?Number(day):day', sub)          # not a number: sent as typed, refused by the server
        self.assertIn('"Content-Type":"application/json"', sub)

    @needs_node
    def test_the_body_carries_every_field(self):
        # a stray comment once swallowed dns_resolvers, so a resolver change was silently dropped:
        # the form is submitted and what reaches the server is checked, field by field (#111)
        code = JS_DOM + "const rangeLabel=()=>'1h';\n" + js_defs(
            "const $=", "const esc=", "let settingsDirty=", "function renderSettings(", '$("#settings").addEventListener("submit"')
        fill = ("$('#set-day').value=' 15 ';$('#set-resolvers').value='gateway, 9.9.9.9';$('#set-probe').value='example.org';"
                "$('#set-alert_outages').checked=true;$('#set-notify_level').value='bad';"
                "$('#set-dashboard_url').value=' http://192.168.1.60:8080 ';"
                "_reply={status:200,body:{values:{},read_only:{},public_resolvers:[]}};")
        sent, status = run_js(code + fill, "($('#settings').dispatch('submit')).then(()=>[_fetches[0],$('#set-status').textContent])")
        self.assertEqual((sent["url"], sent["method"]), ("/api/settings", "POST"))
        self.assertEqual(sent["body"], {"usage_month_starts": 15, "dns_resolvers": ["gateway", "9.9.9.9"],
                                        "dns_probe_name": "example.org", "alert_attention": False, "alert_outages": True,
                                        "alert_calls": False, "alert_new_devices": False, "notify_level": "bad",
                                        "dashboard_url": "http://192.168.1.60:8080"})
        self.assertEqual(status, "Saved.")
        # emptied fields go back to config.json's (null)
        sent = run_js(code + "_reply={status:400,body:{error:'no'}};",
                      "($('#settings').dispatch('submit')).then(()=>[_fetches[0].body,$('#set-status').textContent])")
        self.assertEqual({k: sent[0][k] for k in ("usage_month_starts", "dns_resolvers", "dns_probe_name", "dashboard_url")},
                         dict.fromkeys(("usage_month_starts", "dns_resolvers", "dns_probe_name", "dashboard_url")))
        self.assertEqual(sent[1], "Not saved: no")

    def test_the_schedule_is_shown_not_edited(self):
        page = page_code()
        self.assertIn('<span id="set-speedtest" class="muted"></span>', page)
        self.assertNotIn('id="set-speedtest" type=', page)


class DashboardAlertsTest(unittest.TestCase):
    """Step 4.4a: the header's alert count and the alerts list in the side panel."""

    def fn(self, name):
        page = page_code()
        i = page.index(f"function {name}(")
        return page[i:page.index("\n}\n", i)]

    def test_alerts_is_an_item_and_opens_the_panel(self):
        page = page_code()
        self.assertIn('|alerts)$/', page)
        self.assertIn('it==="alerts"?"alerts"', page)
        self.assertIn('go({item:"alerts"})', page)

    def test_server_text_is_escaped_and_links_are_checked(self):
        a = self.fn("renderAlerts")
        self.assertIn("esc(r.text)", a)
        self.assertIn("validItem(r.item)?r.item:null", a)
        self.assertIn("tabName(r.tab)", a)
        self.assertIn('fetch("/api/alerts/seen",{method:"POST",headers:{"Content-Type":"application/json"}', a)

    def test_the_count_is_said_to_screen_readers(self):
        c = self.fn("renderAlertCount")
        self.assertIn('b.setAttribute("aria-label",`Alerts: ${n} active', c)
        self.assertIn('$("#alertcount").textContent=', c)


class DashboardSpeedtestTest(unittest.TestCase):
    """Step 4.6: the speed test panel on Usage."""

    def test_started_only_by_the_button_and_text_is_escaped(self):
        page = page_code()
        i = page.index("function renderSpeedtest(")
        r = page[i:page.index("\n}\n", i)]
        self.assertIn("esc(r.error)", r)
        self.assertIn("LV[r.level]", r)
        self.assertIn('$("#strun").disabled=s.running||!s.server;', r)      # no second start; none with a bad server (#99)
        self.assertIn("$(\"#stabout\").textContent=", r)                     # says where the data goes, as text
        self.assertEqual(page.count('fetch("/api/speedtest",{method:"POST"'), 1)   # one place starts a test: the button

    # #122: the router's shaping caps what a test can measure - the panel says so
    CODE = JS_DOM + js_defs("const $=", "const esc=", "const ms=", "const mbps=", "let routerLink=", "const PROTO=",
                            "function shapingText(", "function linkRows(", "let stPolling=", "function renderSpeedtest(")
    SQM = {"enabled": True, "down_mbps": 45, "up_mbps": 9, "qdisc": "cake", "autorate": False}

    @needs_node
    def test_the_router_s_shaping_is_explained(self):
        base = {"running": False, "phase": None, "error": None, "results": [], "server": "speed.cloudflare.com",
                "server_problem": None, "schedule": "off"}
        about = run_js(self.CODE, "[" + ",".join(
            f"(renderSpeedtest({json.dumps({**base, 'shaping': s})}),$('#stabout').textContent)"
            for s in (self.SQM, {**self.SQM, "enabled": False}, None)) + "]")
        self.assertIn("Your router shapes traffic to ↓ 45 Mb/s · ↑ 9.0 Mb/s (SQM, cake) so a busy line stays responsive: "
                      "results can't go above that.", about[0])
        self.assertNotIn("shapes", about[1])                                   # shaping off: nothing to explain
        self.assertNotIn("shapes", about[2])                                   # no router reading

    @needs_node
    def test_router_panel_rows(self):
        rows = run_js(self.CODE, "[linkRows({wan:{protocol:'pppoe',connected:true,ip:'1.2.3.4'},sqm:%s}),"
                                 "linkRows({wan:{protocol:'<i>x</i>',connected:false,ip:null},sqm:null}),linkRows(null)]"
                      % json.dumps(self.SQM))
        self.assertEqual(rows[0], [["Connection", "PPPoE · connected"], ["Internet address", "1.2.3.4"],
                                   ["Traffic shaping", "↓ 45 Mb/s · ↑ 9.0 Mb/s (SQM, cake)"]])
        self.assertEqual(rows[1][0], ["Connection", "&lt;i&gt;x&lt;/i&gt; · not connected"])   # escaped for kv()
        self.assertEqual(rows[2], [["Connection", None], ["Internet address", None], ["Traffic shaping", None]])


class DashboardSecurityTest(unittest.TestCase):
    """#131: the Security panel on System."""
    CODE = JS_DOM + "const LV={good:'good',warn:'warn',bad:'bad',unknown:'unknown'};\n" + js_defs(
        "const $=", "const esc=", "function renderSecurity(")

    @needs_node
    def test_items_firmware_and_the_states_without_a_reading(self):
        v = {"available": True, "level": "warn", "items": [
            {"key": "upnp", "level": "warn", "text": "UPnP is on: <devices>"},
            {"key": "closed", "level": "good", "text": "Closed: DMZ, SSH."}],
            "firmware": [{"what": "Router (mt6000)", "version": "4.11.0", "date": "2026-09-24 15:49:08"},
                         {"what": "Office (mesh)", "version": "1.3.5 Build 26071712", "date": None}]}
        out = run_js(self.CODE, "[" + ",".join(f"(renderSecurity({json.dumps(s)}),[$('#security').innerHTML,$('#firmware').textContent])"
                                               for s in (v, {"available": False, "items": [], "firmware": []}, {}, None)) + "]")
        html, fw = out[0]
        self.assertIn('<span class="dot warn"></span>UPnP is on: &lt;devices&gt;', html)       # escaped
        self.assertIn('<span class="dot good"></span>Closed: DMZ, SSH.', html)
        self.assertEqual(fw, "Firmware: Router (mt6000) 4.11.0 (2026-09-24) · Office (mesh) 1.3.5 Build 26071712")
        self.assertIn("Needs the router's password", out[1][0])
        self.assertIn("Couldn't load", out[2][0])                                               # a failed fetch
        self.assertIn("Couldn't load", out[3][0])


class DashboardDeviceTypeTest(unittest.TestCase):
    """#122: the Deco's own device types and networks read as words."""

    @needs_node
    def test_iot_devices_get_an_icon_and_networks_read_as_words(self):
        code = js_defs("const ownProp=", "const KIND=", "const kindIcon=", "const KIND_WORD_OF=", "const NETWORK_WORD=")
        out = run_js(code, "[kindIcon('iot_device'),KIND_WORD_OF.iot_device,kindIcon('phone'),kindIcon('<b>'),"
                           "kindIcon('constructor'),kindIcon('toString'),NETWORK_WORD.guest,NETWORK_WORD.iot,NETWORK_WORD.main]")
        # a type named like an Object property finds nothing (#126 review)
        self.assertEqual(out, ["💡 ", "smart home device", "📱 ", "", "", "", "guest network", "IoT network", "main"])
        page = page_code()
        self.assertIn('["Network",n.network?esc(ownProp(NETWORK_WORD,n.network)||n.network):null]', page)   # escaped in kv()
        self.assertIn("ownProp(KIND_WORD_OF,n.devkind)", page)


class DashboardDigestTest(unittest.TestCase):
    """Step 4.7: last week on the Overview."""

    def test_every_figure_is_escaped(self):
        page = page_code()
        i = page.index("function renderDigest(")
        r = page[i:page.index("\n}\n", i)]
        self.assertIn("esc(w.headline)", r)
        self.assertIn("<dt>${esc(k)}</dt><dd>${esc(v)}</dd>", r)              # names (devices, the top user) included
        self.assertIn("if(!w) return;", r)                                     # until the first is built, the note stays
        self.assertIn("day(w.week_end-43200)", r)                              # #100: noon of the last day, right across clock changes


class DashboardQualityTest(unittest.TestCase):
    """#101: calls and DNS over the range, on History."""

    def test_both_charts_break_at_gaps_and_take_theme_colours(self):
        page = page_code()
        i = page.index("function renderQuality(")
        r = page[i:page.index("\n}\n", i)]
        self.assertIn("withGaps(series,bucket)", r)
        self.assertIn("pts(q.mos,q.bucket_s)", r)
        self.assertIn("pts(r.points,q.bucket_s)", r)
        self.assertIn("CC.teal", r)
        self.assertNotRegex(r, r"#[0-9a-fA-F]{6}")


class DashboardSetupTest(unittest.TestCase):
    """Step 5.1: the Setup checklist on System."""

    def test_server_text_is_escaped_and_passwords_are_never_shown(self):
        page = page_code()
        i = page.index("function renderSetup(")
        r = page[i:page.index("\n}\n", i)]
        for s in ("esc(i.title)", "esc(i.text)", "esc(i.action)", "LV[i.level]"):
            self.assertIn(s, r)
        self.assertIn('$("#setup-creds").textContent=', r)                 # text, never HTML
        self.assertIn('c.router?"set":"not set"', r)                       # only whether, never what

    # the Setup panel and its forms, run against the stand-in browser (#111)
    SETUP = (JS_DOM + "const LV={good:'good',bad:'bad'};\n" + js_defs(
        "const $=", "const esc=", "function renderSetup(", "const CRED_FIELDS=", '$("#credsform").addEventListener("submit"',
        '$("#notifytestbtn").addEventListener("click"'))
    CHECKLIST = {"items": [], "credentials_file": "C:/Users/x/.hearth/router.env", "local": True,
                 "credentials": {"router": True, "mesh": False, "notify": ["ntfy", None], "notify_token": True}}

    @needs_node
    def test_setup_says_only_whether_and_which_kind_and_the_form_is_for_the_hearth_computer(self):
        out = run_js(self.SETUP, "[" + ",".join(
            f"(renderSetup({json.dumps({**self.CHECKLIST, 'local': local})}),"
            "[$('#setup-creds').textContent,$('#credsform').hidden,$('#notifytest').hidden])" for local in (True, False)) + "]")
        (text, form_hidden, test_hidden), (_, remote_form_hidden, _) = out
        self.assertIn("router password set, Deco password not set, notifications ntfy (with a ntfy token).", text)
        self.assertEqual((form_hidden, test_hidden, remote_form_hidden), (False, False, True))
        page = page_code()
        self.assertIn('<form id="credsform" class="settings" hidden autocomplete="off">', page)
        self.assertNotIn(".value=d", page)                                   # never filled from the server

    @needs_node
    def test_saving_sends_what_was_typed_and_removals_then_clears_the_form(self):
        fill = ("$('#cred-router').value=' pass word ';$('#cred-notify').value='  https://ntfy.sh/topic  ';"
                "$('#rm-notify_2').checked=true;"
                f"_reply={{status:200,body:{json.dumps(self.CHECKLIST)}}};")
        sent, after, status = run_js(self.SETUP + fill, "($('#credsform').dispatch('submit')).then(()=>[_fetches[0],"
                                     "CRED_FIELDS.map(k=>$('#cred-'+k).value).concat($('#rm-notify_2').checked),"
                                     "$('#cred-status').textContent])")
        self.assertEqual((sent["url"], sent["method"]), ("/api/setup/credentials", "POST"))
        self.assertEqual(sent["body"], {"router": " pass word ", "notify": "https://ntfy.sh/topic", "notify_2": ""})
        self.assertEqual(after, ["", "", "", "", "", False])                   # cleared once saved
        self.assertEqual(status, "Saved. Hearth will use it within a minute.")
        self.assertEqual(run_js(self.SETUP, "($('#credsform').dispatch('submit')).then(()=>[_fetches.length,$('#cred-status').textContent])"),
                         [0, "Type something to save, or tick what to remove."])

    @needs_node
    def test_the_test_button_reports_each_channel(self):
        fill = "_reply={status:200,body:{results:[{kind:'ntfy',ok:true},{kind:'webhook',ok:false,error:'HTTP 403'}]}};"
        self.assertEqual(run_js(self.SETUP + fill, "($('#notifytestbtn').dispatch('click')).then(()=>[_fetches[0].url,$('#notifytest-status').textContent])"),
                         ["/api/notify/test", "ntfy: sent · webhook: failed (HTTP 403)"])
        fill = "_reply={status:429,body:{error:'a test was sent under a minute ago - try again in 30 s'}};"
        self.assertEqual(run_js(self.SETUP + fill, "($('#notifytestbtn').dispatch('click')).then(()=>$('#notifytest-status').textContent)"),
                         "a test was sent under a minute ago - try again in 30 s")


class DashboardWelcomeTest(unittest.TestCase):
    """Step 5.3: the first-run welcome on the Overview."""

    # renderWelcome and its pieces, run against the stand-in browser (#111)
    WELCOME = JS_DOM + 'const rangeLabel=()=>"1h";\n' + js_defs(
        "const $=", "const esc=", "const save=", "function hashFor(", "const WELCOME_KEY=",
        "let welcomeClosed=", "let welcomeHtml=", "function renderWelcome(", '$("#welcomeclose")')
    # one render: [hidden, the text] - st.updated and st.started are the server's clock
    SHOW = ("(st=>{renderWelcome(st);const w=$('#welcome');return [w.hidden,$('#welcometext').innerHTML]})")

    def welcome(self, setup, expr):
        return run_js(self.WELCOME + setup, expr)

    @needs_node
    def test_shown_while_new_then_hidden(self):
        out = self.welcome("const show=" + self.SHOW + ";", "[" + ",".join(
            f"show({{started:0,updated:{age},layout_known:{known}}})" for age, known in
            ((60, "false"), (300, "true"), (660, "true"), (900, "false"), (1860, "false"))) + ",show(null)]")
        (h1, t1), (h5, t5), (h11, _), (h15, t15), (h31, _), (hnone, _) = out
        self.assertFalse(h1)
        self.assertIn("started 1 minute ago", t1)
        self.assertIn("works out the layout over about 5 minutes", t1)
        self.assertIn('href="#/system?range=1h"', t1)
        self.assertFalse(h5)
        self.assertIn("has worked out the layout", t5)
        self.assertTrue(h11)                                   # past 10 minutes with the layout known
        self.assertFalse(h15)                                  # layout unknown: kept, and says so honestly
        self.assertIn("is still working out the layout", t15)
        self.assertTrue(h31)                                   # never for good (#110 review)
        self.assertTrue(hnone)

    @needs_node
    def test_got_it_hides_it_for_good_even_with_storage_blocked(self):
        st = "{started:0,updated:60,layout_known:false}"
        for blocked in ("false", "true"):
            hidden, stored = self.welcome(
                f"_storageBlocked={blocked};const show={self.SHOW};show({st});$('#welcomeclose').click();",
                f"[show({st})[0],_store.hearth_welcome_done??null]")
            self.assertTrue(hidden, blocked)
            self.assertEqual(stored, None if blocked == "true" else "1")
        # remembered across page loads (a fresh run with the stored flag)
        self.assertTrue(self.welcome(f"_store.hearth_welcome_done='1';const show={self.SHOW};", f"show({st})[0]"))

    @needs_node
    def test_the_text_is_written_only_when_it_changed(self):
        writes = self.welcome(f"const show={self.SHOW};",
                              "(show({started:0,updated:60,layout_known:false}),show({started:0,updated:70,layout_known:false}),"
                              "show({started:0,updated:200,layout_known:false}),$('#welcometext').writes)")
        self.assertEqual(writes, 2)   # 60 s and 70 s read the same ("1 minute"); 200 s doesn't (#112)

    def test_timestamps_are_not_cut_to_32_bits_and_tiles_link_before_the_first_render(self):
        page = page_code()
        js = page[page.index("<script"):]
        self.assertNotRegex(js, r"(start|end|ts)\|0")   # x|0 is a 32-bit int: wrong from 2038 (#71)
        for t in ("system", "history", "usage", "network"):
            self.assertIn(f'<a class="livefig tile" data-tab="{t}" href="#/{t}">', page)   # focusable at once

    def test_status_says_when_hearth_started_and_whether_the_layout_is_known(self):
        c = mem_db()
        self.addCleanup(c.close)
        analysis.clear_cache()
        st = analysis.status(c)
        self.assertEqual(st["started"], round(analysis.HEARTH_STARTED))
        self.assertFalse(st["layout_known"])


class DashboardChartGapsTest(unittest.TestCase):
    """#81: hours with no data are a break in the line, not the last value held across them."""

    @needs_node
    def test_gaps_become_breaks(self):
        page = page_code()
        fn = page[page.index("const GAP="):page.index("\n}\n", page.index("function withGaps(")) + 2]
        script = fn + "\nconsole.log(JSON.stringify(withGaps([[0,1],[240,1],[480,1],[3600,1]],240).map(p=>p[1]===GAP?null:p[0])));"
        out = subprocess.run(["node", "-e", script], capture_output=True, text=True, timeout=30, check=True).stdout
        self.assertEqual(json.loads(out), [0, 240, 480, None, 3600])   # one break, after the last bucket before the gap

    @needs_node
    def test_traffic_drops_to_zero_across_a_gap(self):
        page = page_code()
        i = page.index("function zeroGaps(")
        fn = page[i:page.index("\n}\n", i) + 2]
        script = fn + "\nconsole.log(JSON.stringify(zeroGaps([[0,5,1],[720,6,1],[7200,4,1]],720)));"
        out = subprocess.run(["node", "-e", script], capture_output=True, text=True, timeout=30, check=True).stdout
        self.assertEqual(json.loads(out), [[0, 5, 1], [720, 6, 1], [1440, 0, 0], [6480, 0, 0], [7200, 4, 1]])
        self.assertIn("points:zeroGaps(d.points,s.bucket_s)", page)

    def test_both_charts_use_it(self):
        self.assertIn("withGaps(ser.series[c.id]||[],ser.bucket_s)", page_code())


class DashboardScriptFileTest(unittest.TestCase):
    def test_script_served_fresh_and_versioned_with_the_page(self):
        from hearth import web
        self.assertEqual(web._STATIC["/dashboard.js"][0], "dashboard.js")
        self.assertNotIn("dashboard.js", web._LONG_CACHE)                 # revalidated on every load
        self.assertIn("chart.umd.js", web._LONG_CACHE)
        self.assertEqual(web.dashboard_version().count("/"), 1)           # markup and script


class DashboardTrustBannerTest(unittest.TestCase):
    def banner(self):
        page = page_code()
        return page[page.index("function renderTrust("):page.index("function renderMesh(")]

    def test_reason_from_the_server_escaped(self):
        b = self.banner()
        self.assertIn("esc(p.reason)", b)
        self.assertNotIn("${p.reason}", b)

    def test_new_keys_worded_apart_from_a_new_certificate(self):
        b = self.banner()
        self.assertIn('p.kind==="keys"', b)
        self.assertIn("Trust the new keys", b)
        self.assertIn("Trust the new certificate", b)
        self.assertIn("p.old===p.new", b)        # new keys may come with a new certificate too


class DashboardPlacementTest(unittest.TestCase):
    def mesh_tree(self):
        page = page_code()
        return page[page.index("function buildMeshTree("):page.index("function buildTree(")]

    def test_mesh_map_uses_server_placement(self):
        tree = self.mesh_tree()
        self.assertIn("m.unlisted", tree)
        self.assertIn("Location unknown", tree)
        self.assertIn('placement==="timing"', tree)
        self.assertNotIn("No Deco lists these now", page_code())

    def test_nothing_the_mesh_draws_is_drawn_again(self):
        tree = self.mesh_tree()
        self.assertIn("!drawn.has(u.id)&&!queued.has(u.id)", tree)       # no duplicates under a unit
        self.assertIn('n.edge!=="loose"', tree)                          # timing children aren't renamed

    def test_timing_match_without_its_unit_on_the_map_says_so(self):
        tree = self.mesh_tree()
        loose = tree[tree.index('const LOOSE="Location unknown"'):]
        self.assertIn('unlisted[id]?.placement==="timing"', loose)
        self.assertIn("a unit that isn't on the map", loose)

    def test_device_records_prefer_the_online_row(self):
        # several rows can share an id (a MAC also seen at an old address): one lookup, online wins
        page = page_code()
        self.assertNotIn("Object.fromEntries(dev.map(d=>[d.id,d]))", page)
        self.assertEqual(page.count("devInfo(dev)"), 4)   # both layouts, the devices table, the side panel's index

    def test_timing_layout_untouched(self):
        page = page_code()
        timing = page[page.index("function buildTree("):page.index("function renderMap(")]
        self.assertNotIn("unlisted", timing)                 # placement only applies to the mesh map


if __name__ == "__main__":
    unittest.main()
