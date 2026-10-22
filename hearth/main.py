import os
import socket
import sys
import threading
import traceback
from http.server import ThreadingHTTPServer

from . import analysis, collectors, store
from .config import CFG, DB_PATH, IS_WIN, LEGACY_DB_PATH, log
from .web import Handler

RESTART_DELAY_S = 15

# a browser closing a tab or refreshing mid-request; nothing went wrong on our side
CLIENT_DISCONNECTS = (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)


class Server(ThreadingHTTPServer):
    daemon_threads = True
    # the dashboard fetches ~7 endpoints at once; the default listen queue of 5 makes Windows
    # refuse the rest outright (it doesn't queue past the backlog)
    request_queue_size = 64
    # at most this many requests are handled at once (a bounded worker pool, as waitress or
    # gunicorn's threaded workers do); further connections wait in the listen queue instead of
    # each getting a thread, so clients that open many connections and stall can't make the
    # server start threads without limit. Each stalled one is dropped after Handler.timeout
    max_handlers = 32

    def __init__(self, *args, **kwargs):
        self._slots = threading.BoundedSemaphore(self.max_handlers)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        self._slots.acquire()  # blocks accepting until a handler is free
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()  # the thread never started, so it won't release the slot
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def handle_error(self, request, client_address):
        if isinstance(sys.exc_info()[1], CLIENT_DISCONNECTS):
            return  # don't print a traceback for an ordinary disconnect
        super().handle_error(request, client_address)


def _migrate_legacy_db():
    """Carry history over from the pre-rename database file. Runs only after this process
    holds the web port, so no other copy can have the file open; the main file moves last,
    so an interrupted move leaves the old database usable on the next start."""
    if os.path.exists(LEGACY_DB_PATH) and not os.path.exists(DB_PATH):
        for suffix in ("-wal", "-shm", ""):
            if os.path.exists(LEGACY_DB_PATH + suffix):
                os.replace(LEGACY_DB_PATH + suffix, DB_PATH + suffix)
                log(f"moved netmon.db{suffix} to hearth.db{suffix}")


def supervise(name, fn, args, stop):
    """Run a background job forever: if it crashes (any exception, not just database ones),
    log the traceback and start it again, so one bad reading can't silently stop monitoring."""
    while not stop.is_set():
        try:
            fn(*args)
            if stop.is_set():
                return
            log(f"{name}: stopped unexpectedly - restarting")
        except Exception:
            log(f"{name}: crashed - restarting in {RESTART_DELAY_S}s\n{traceback.format_exc()}")
        stop.wait(RESTART_DELAY_S)


def main():
    port = int(CFG["web_port"])
    try:
        srv = Server(("0.0.0.0", port), Handler)
    except OSError:
        log(f"Port {port} is already in use - is Hearth already running? (or change web_port in config.json)")
        sys.exit(1)
    _migrate_legacy_db()
    store.init_db()

    stop = threading.Event()
    conn = store.db()
    store.add_event(conn, "monitor_start", f"Hearth started on {socket.gethostname()}")
    conn.commit()   # the start is recorded whatever the recheck below does
    try:   # once per change of what counts as a slow spell; a locked database mustn't stop Hearth starting
        dropped = analysis.reclassify_stored_slow(conn)
        if dropped:
            log(f"history: {dropped} stored slow spells no longer count as slow under the current rule")
    except Exception as e:  # noqa: BLE001 - tried again at the next start
        conn.rollback()
        log(f"history: couldn't recheck stored slow spells ({type(e).__name__}: {e}) - will try at the next start")
    conn.commit()
    conn.close()

    core = collectors.CorePingers(stop)
    jobs = [("writer", collectors.writer_loop, (stop,)),
            ("discovery", collectors.discovery_loop, (stop, core)),
            ("devices", collectors.device_poll_loop, (stop,)),
            ("path", collectors.path_loop, (stop, core)),
            ("topology", collectors.topology_loop, (stop,)),
            ("spike_hours", collectors.spike_hours_loop, (stop,)),
            ("router", collectors.router_loop, (stop,)),
            ("mesh", collectors.mesh_loop, (stop,)),
            ("upnp", collectors.upnp_loop, (stop,)),
            ("dns", collectors.dns_loop, (stop,)),
            ("alerts", collectors.alerts_loop, (stop,)),
            ("notify", collectors.notify_loop, (stop,)),
            ("speedtest", collectors.speedtest_loop, (stop,)),
            ("digest", collectors.digest_loop, (stop,)),
            ("backup", collectors.backup_loop, (stop,))]
    if IS_WIN:
        jobs += [("host", collectors.host_loop, (stop,)),
                 ("wifi", collectors.wifi_loop, (stop,)),
                 ("traffic", collectors.traffic_loop, (stop,))]
    for name, fn, args in jobs:
        threading.Thread(target=supervise, args=(name, fn, args, stop), daemon=True, name=name).start()

    try:
        gw, lan, me = collectors.network_settings()
    except ValueError as e:  # e.g. a malformed discovery_subnet; the discovery job logs it too
        log(f"network settings: {e}")
        gw = lan = me = None
    log(f"Hearth running. Router {gw}, network {lan}. Dashboard: http://{me or 'localhost'}:{port}  (Ctrl+C to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        srv.server_close()
        log("Stopped.")
