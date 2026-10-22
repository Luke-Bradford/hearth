"""How the computer running Hearth is doing: CPU, memory, the commit charge (memory programs
have reserved - when it nears its limit, Windows slows and programs fail even with RAM free),
the kernel's memory pools (a leaking driver shows up here), and which processes hold the most
committed memory (a leaking program shows up there).

Read straight from the Windows API with ctypes - no helper processes - so it costs next to
nothing. Other systems: not supported yet (the reader returns None and the panel stays off).
"""
import ctypes
import os
import re
import struct
import time
from ctypes import wintypes

from .config import IS_WIN

_SIZE_T = ctypes.c_size_t


class _MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [("dwLength", wintypes.DWORD), ("dwMemoryLoad", wintypes.DWORD),
                ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]


class _PERFORMANCE_INFORMATION(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("CommitTotal", _SIZE_T), ("CommitLimit", _SIZE_T),
                ("CommitPeak", _SIZE_T), ("PhysicalTotal", _SIZE_T), ("PhysicalAvailable", _SIZE_T),
                ("SystemCache", _SIZE_T), ("KernelTotal", _SIZE_T), ("KernelPaged", _SIZE_T),
                ("KernelNonpaged", _SIZE_T), ("PageSize", _SIZE_T), ("HandleCount", wintypes.DWORD),
                ("ProcessCount", wintypes.DWORD), ("ThreadCount", wintypes.DWORD)]


class _UNICODE_STRING(ctypes.Structure):
    _fields_ = [("Length", wintypes.USHORT), ("MaximumLength", wintypes.USHORT), ("Buffer", ctypes.c_void_p)]


class _SYSTEM_PROCESS_INFORMATION(ctypes.Structure):
    """The kernel's own per-process record (what Task Manager reads): every process, including
    services an ordinary user can't open. Natural alignment matches the 64-bit layout."""
    _fields_ = [("NextEntryOffset", wintypes.ULONG), ("NumberOfThreads", wintypes.ULONG),
                ("WorkingSetPrivateSize", ctypes.c_longlong), ("HardFaultCount", wintypes.ULONG),
                ("NumberOfThreadsHighWatermark", wintypes.ULONG), ("CycleTime", ctypes.c_ulonglong),
                ("CreateTime", ctypes.c_longlong), ("UserTime", ctypes.c_longlong),
                ("KernelTime", ctypes.c_longlong), ("ImageName", _UNICODE_STRING),
                ("BasePriority", ctypes.c_long), ("UniqueProcessId", ctypes.c_void_p),
                ("InheritedFromUniqueProcessId", ctypes.c_void_p), ("HandleCount", wintypes.ULONG),
                ("SessionId", wintypes.ULONG), ("UniqueProcessKey", ctypes.c_void_p),
                ("PeakVirtualSize", _SIZE_T), ("VirtualSize", _SIZE_T), ("PageFaultCount", wintypes.ULONG),
                ("PeakWorkingSetSize", _SIZE_T), ("WorkingSetSize", _SIZE_T),
                ("QuotaPeakPagedPoolUsage", _SIZE_T), ("QuotaPagedPoolUsage", _SIZE_T),
                ("QuotaPeakNonPagedPoolUsage", _SIZE_T), ("QuotaNonPagedPoolUsage", _SIZE_T),
                ("PagefileUsage", _SIZE_T), ("PeakPagefileUsage", _SIZE_T), ("PrivatePageCount", _SIZE_T)]


class _SERVICE_STATUS_PROCESS(ctypes.Structure):
    _fields_ = [("dwServiceType", wintypes.DWORD), ("dwCurrentState", wintypes.DWORD),
                ("dwControlsAccepted", wintypes.DWORD), ("dwWin32ExitCode", wintypes.DWORD),
                ("dwServiceSpecificExitCode", wintypes.DWORD), ("dwCheckPoint", wintypes.DWORD),
                ("dwWaitHint", wintypes.DWORD), ("dwProcessId", wintypes.DWORD),
                ("dwServiceFlags", wintypes.DWORD)]


class _ENUM_SERVICE_STATUS_PROCESSW(ctypes.Structure):
    _fields_ = [("lpServiceName", wintypes.LPWSTR), ("lpDisplayName", wintypes.LPWSTR),
                ("ServiceStatusProcess", _SERVICE_STATUS_PROCESS)]


POOL_TAGS_TOP = 15
POOL_TAG_SIZE = 40   # SYSTEM_POOLTAG on 64-bit Windows: tag, paged allocs/frees, (pad), paged used,
                     # non-paged allocs/frees, non-paged used; the array starts 8 bytes in
TAG_RE_BYTES = re.compile(rb"[\x20-\x7e]{4}")


def parse_pool_tags(raw, top=POOL_TAGS_TOP):
    """The SystemPoolTagInformation reply -> {tag: (non-paged bytes, live allocations)}, the
    `top` biggest. Entries past the bytes the kernel filled in, and tags that aren't printable,
    are skipped."""
    if len(raw) < 8:
        return {}
    count = struct.unpack_from("<I", raw, 0)[0]
    rows = []
    for i in range(min(count, (len(raw) - 8) // POOL_TAG_SIZE)):
        tag, _pa, _pf, _pu, na, nf, nu = struct.unpack_from("<4sIIxxxxQIIQ", raw, 8 + i * POOL_TAG_SIZE)
        if nu and TAG_RE_BYTES.fullmatch(tag):
            rows.append((nu, tag.decode("ascii"), max(0, na - nf)))
    rows.sort(reverse=True)
    return {tag: (nu, live) for nu, tag, live in rows[:top]}


DRIVERS_DIR = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "drivers")
KERNEL_FILE = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "ntoskrnl.exe")
DRIVER_SCAN_MAX = 64 * 1024 * 1024   # a driver file bigger than this isn't read


def tag_owners(tags, folder=None, kernel=None):
    """{tag: {"file", "company", "product", "description"} or None}: the one driver file in
    `folder` whose code carries the tag - how pool tags are traced to a driver by hand (a driver
    passes its tag as a 4-character constant). None when it's in Windows' own kernel, in more
    than one driver (a shared tag, like "File"), or in none. Reads every driver once - seconds,
    so the caller does it rarely and keeps the answer."""
    folder, kernel = folder or DRIVERS_DIR, kernel or KERNEL_FILE
    want = {t: t.encode("ascii") for t in tags if isinstance(t, str) and TAG_RE_BYTES.fullmatch(t.encode("ascii", "replace"))}
    found = {t: [] for t in want}

    def scan(path):
        try:
            if os.path.getsize(path) > DRIVER_SCAN_MAX:
                return
            with open(path, "rb") as f:
                data = f.read()
        except OSError:
            return
        for t, b in want.items():
            if b in data:
                found[t].append(path)
    try:
        names = sorted(n for n in os.listdir(folder) if n.lower().endswith(".sys"))
    except OSError:
        names = []
    for n in names:
        scan(os.path.join(folder, n))
    in_kernel = set()
    if os.path.exists(kernel):
        before = {t: len(v) for t, v in found.items()}
        scan(kernel)
        in_kernel = {t for t, v in found.items() if len(v) > before[t]}
    out = {}
    for t in want:
        files = found[t]
        out[t] = None if t in in_kernel or len(files) != 1 else {"file": os.path.basename(files[0]),
                                                                 **file_version(files[0])}
    return out


def file_version(path):
    """{"company", "product", "description"} from a file's version resource ("" where absent)."""
    out = {"company": "", "product": "", "description": ""}
    if not IS_WIN:
        return out
    try:
        ver = ctypes.WinDLL("version")
        size = ver.GetFileVersionInfoSizeW(path, None)
        if not size:
            return out
        buf = ctypes.create_string_buffer(size)
        if not ver.GetFileVersionInfoW(path, 0, size, buf):
            return out
        ptr, n = ctypes.c_void_p(), wintypes.UINT()
        if not ver.VerQueryValueW(buf, "\\VarFileInfo\\Translation", ctypes.byref(ptr), ctypes.byref(n)) or n.value < 4:
            return out
        lang, cp = struct.unpack("<HH", ctypes.string_at(ptr.value, 4))
        for key, name in (("company", "CompanyName"), ("product", "ProductName"), ("description", "FileDescription")):
            if ver.VerQueryValueW(buf, f"\\StringFileInfo\\{lang:04x}{cp:04x}\\{name}", ctypes.byref(ptr), ctypes.byref(n)) and n.value:
                out[key] = ctypes.wstring_at(ptr.value, n.value).rstrip("\x00").strip()[:80]
    except (OSError, AttributeError, ValueError):
        pass
    return out


def _ft(ft):
    return (ft.dwHighDateTime << 32) | ft.dwLowDateTime


SVC_TTL_S = 600  # how long service-host names are reused (see Reader.service_names)


class Reader:
    """Call sample() every minute or so; CPU is measured between calls."""

    def __init__(self):
        # the kernel structures below are laid out for 64-bit Windows; a 32-bit Python would
        # misread them, so the reader is simply off there
        self.ok = IS_WIN and ctypes.sizeof(ctypes.c_void_p) == 8
        self._prev_cpu = None
        # service-host names, and when they were read (None = never; not 0, because on
        # Windows time.monotonic() counts from boot and is under the TTL for 10 minutes)
        self._svc, self._svc_ts, self._svc_retry_at = {}, None, 0.0
        if self.ok:
            self._k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            self._k32.GetTickCount64.restype = ctypes.c_ulonglong
            self._ntdll = ctypes.WinDLL("ntdll")
            self._ntdll.NtQuerySystemInformation.argtypes = [wintypes.ULONG, ctypes.c_void_p, wintypes.ULONG,
                                                             ctypes.POINTER(wintypes.ULONG)]
            self._ntdll.NtQuerySystemInformation.restype = ctypes.c_long

    def reset_cpu(self):
        """The next sample only primes the CPU counters (its cpu_pct is None)."""
        self._prev_cpu = None

    def _cpu_times(self):
        idle, kernel, user = wintypes.FILETIME(), wintypes.FILETIME(), wintypes.FILETIME()
        if not self._k32.GetSystemTimes(ctypes.byref(idle), ctypes.byref(kernel), ctypes.byref(user)):
            return None
        return _ft(idle), _ft(kernel) + _ft(user)  # kernel time includes idle time

    def sample(self):
        """{cpu_pct, mem_total, mem_avail, commit, commit_limit, pool_paged, pool_nonpaged,
        handles, processes, threads, uptime_s} in bytes / counts, or None if unsupported."""
        if not self.ok:
            return None
        ms = _MEMORYSTATUSEX(dwLength=ctypes.sizeof(_MEMORYSTATUSEX))
        pi = _PERFORMANCE_INFORMATION(cb=ctypes.sizeof(_PERFORMANCE_INFORMATION))
        if not self._k32.GlobalMemoryStatusEx(ctypes.byref(ms)) or \
                not self._k32.K32GetPerformanceInfo(ctypes.byref(pi), pi.cb):
            return None
        page = pi.PageSize
        cpu, now = None, self._cpu_times()
        if now and self._prev_cpu:
            d_idle, d_total = now[0] - self._prev_cpu[0], now[1] - self._prev_cpu[1]
            if d_total > 0:
                cpu = round(100.0 * (d_total - d_idle) / d_total, 1)
        self._prev_cpu = now
        return {"cpu_pct": cpu, "mem_total": ms.ullTotalPhys, "mem_avail": ms.ullAvailPhys,
                "commit": pi.CommitTotal * page, "commit_limit": pi.CommitLimit * page,
                "pool_paged": pi.KernelPaged * page, "pool_nonpaged": pi.KernelNonpaged * page,
                "handles": pi.HandleCount, "processes": pi.ProcessCount, "threads": pi.ThreadCount,
                "uptime_s": self._k32.GetTickCount64() // 1000}

    def processes(self, top=15):
        """[(name, committed bytes, process count, handles, most handles in one process)] for
        the programs holding the most memory or handles, summed by name (Chrome's many
        processes count as one; a Windows service host is named after its service). The
        per-process maximum is what leak warnings use - 37 healthy Chrome processes can add
        up to a lot without any one of them leaking."""
        if not self.ok:
            return []
        totals = {}
        services = self.service_names()
        for pid, name, private, handles in self._process_table():
            name = name[:-4] if name.lower().endswith(".exe") else name
            if name.lower() == "svchost" and pid in services:
                name = f"svchost ({services[pid]})"
            t = totals.setdefault(name, [0, 0, 0, 0])
            t[0] += private
            t[1] += 1
            t[2] += handles
            t[3] = max(t[3], handles)
        rows = [(n, b, c, hd, mx) for n, (b, c, hd, mx) in totals.items()]
        # the top by memory, plus whichever single processes hold the most handles
        keep = sorted(rows, key=lambda x: -x[1])[:top]
        keep += [r for r in sorted(rows, key=lambda x: -x[4])[:5] if r not in keep]
        return keep

    def _process_table(self):
        """[(pid, image name, committed bytes, handles)] for every process, from one kernel call
        (NtQuerySystemInformation / SystemProcessInformation) - no process is opened."""
        ntdll = self._ntdll
        size = 1 << 20
        for _ in range(6):  # the table grows while we look: retry with the size it asks for
            buf = ctypes.create_string_buffer(size)
            needed = wintypes.ULONG()
            status = ntdll.NtQuerySystemInformation(5, buf, size, ctypes.byref(needed))
            if status == 0:
                break
            if status & 0xFFFFFFFF != 0xC0000004:  # anything but STATUS_INFO_LENGTH_MISMATCH
                return []
            size = max(size * 2, needed.value + (1 << 16))
        else:
            return []
        out, offset, base = [], 0, ctypes.addressof(buf)
        limit = min(size, needed.value or size)
        while True:
            # never read past what the kernel filled in, whatever an entry's offset says
            if offset + ctypes.sizeof(_SYSTEM_PROCESS_INFORMATION) > limit:
                return out
            p = _SYSTEM_PROCESS_INFORMATION.from_address(base + offset)
            pid = p.UniqueProcessId or 0
            name_ok = p.ImageName.Buffer and p.ImageName.Length and \
                base <= p.ImageName.Buffer and p.ImageName.Buffer + p.ImageName.Length <= base + limit
            if name_ok:
                name = ctypes.wstring_at(p.ImageName.Buffer, p.ImageName.Length // 2)
            else:
                name = "System Idle Process" if pid == 0 else f"pid {pid}"
            if pid:
                out.append((pid, os.path.basename(name), p.PagefileUsage, p.HandleCount))
            if not p.NextEntryOffset:
                return out
            offset += p.NextEntryOffset

    def pool_tags(self, top=POOL_TAGS_TOP):
        """{tag: (non-paged bytes, live allocations)} for the `top` tags holding the most
        non-paged kernel memory (NtQuerySystemInformation / SystemPoolTagInformation: each
        driver labels what it allocates with a 4-character tag). No admin rights needed (#127)."""
        if not self.ok:
            return {}
        size = 1 << 18
        for _ in range(6):
            buf = ctypes.create_string_buffer(size)
            needed = wintypes.ULONG()
            status = self._ntdll.NtQuerySystemInformation(22, buf, size, ctypes.byref(needed))
            if status == 0:
                break
            if status & 0xFFFFFFFF != 0xC0000004:
                return {}
            size = max(size * 2, needed.value + (1 << 14))
        else:
            return {}
        return parse_pool_tags(buf.raw[:min(size, needed.value or size)], top)

    _SVC_TTL_S = SVC_TTL_S                # a good answer is reused this long - services rarely move
    _SVC_RETRY_S = 60                     # after a failed read, ask again no sooner than this
    _SVC_STALE_S = 2 * SVC_TTL_S          # older names are dropped: process ids get reused

    def service_names(self):
        """{pid: service display name} for service host processes, via the service manager
        (read-only query). A failed read keeps the last good names until they're _SVC_STALE_S
        old, and is retried at most every _SVC_RETRY_S."""
        now = time.monotonic()
        if self._svc_ts is not None and now - self._svc_ts < self._SVC_TTL_S:
            return self._svc
        if now < self._svc_retry_at:
            return self._svc
        svc = self._read_services()
        if svc:
            self._svc, self._svc_ts = svc, now
        else:
            self._svc_retry_at = now + self._SVC_RETRY_S
            if self._svc_ts is None or now - self._svc_ts >= self._SVC_STALE_S:
                self._svc = {}
        return self._svc

    def _read_services(self):
        """{pid: display name(s)} from the service manager, or {} if it can't be read."""
        svc = {}
        try:
            advapi = ctypes.WinDLL("advapi32", use_last_error=True)
            advapi.OpenSCManagerW.restype = wintypes.HANDLE
            advapi.EnumServicesStatusExW.argtypes = [
                wintypes.HANDLE, ctypes.c_int, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
                wintypes.LPCWSTR]
            advapi.CloseServiceHandle.argtypes = [wintypes.HANDLE]
            scm = advapi.OpenSCManagerW(None, None, 0x0004)  # SC_MANAGER_ENUMERATE_SERVICE
            if not scm:
                return svc
            try:
                # services can appear between the size query and the read (ERROR_MORE_DATA):
                # resume where it stopped until the list is complete
                needed, count, resume = wintypes.DWORD(), wintypes.DWORD(), wintypes.DWORD()
                advapi.EnumServicesStatusExW(scm, 0, 0x30, 1, None, 0, ctypes.byref(needed),
                                             ctypes.byref(count), ctypes.byref(resume), None)
                resume = wintypes.DWORD()
                for _ in range(10):
                    raw = ctypes.create_string_buffer(needed.value + 16384)
                    ok = advapi.EnumServicesStatusExW(scm, 0, 0x30, 1, raw, len(raw), ctypes.byref(needed),
                                                      ctypes.byref(count), ctypes.byref(resume), None)
                    entries = ctypes.cast(raw, ctypes.POINTER(_ENUM_SERVICE_STATUS_PROCESSW))
                    for i in range(count.value):
                        e = entries[i]
                        pid = e.ServiceStatusProcess.dwProcessId
                        if pid and e.lpDisplayName:
                            svc[pid] = (svc[pid] + ", " if pid in svc else "") + e.lpDisplayName
                    if ok or ctypes.get_last_error() != 234:  # 234 = ERROR_MORE_DATA: keep reading
                        break
            finally:
                advapi.CloseServiceHandle(scm)
        except (OSError, AttributeError):
            pass
        return svc


# --------------------------------------------------------------------------- judging it
GB = 1024 ** 3
COMMIT_WARN, COMMIT_BAD = 0.75, 0.90      # share of the commit limit in use
NONPAGED_WARN = 2 * GB                     # a healthy machine sits well under 1 GB
AVAIL_WARN = 0.10                          # share of RAM still available
LEAK_MIN_GROWTH = 1 * GB                   # a program growing this much...
LEAK_MIN_RATIO = 0.5                       # ...and by half again, over at least...
LEAK_MIN_SPAN_S = 6 * 3600                 # ...six hours, without ever shrinking back much
UPTIME_NOTE_S = 21 * 86400
LEAKS_STATE_KEY = "host_leaks"             # state row: programs found leaking at the last check
PROCESS_HANDLES_WARN = 200_000             # busy services hold tens of thousands; millions is a leak
# kernel pool by driver (#127): a tag growing this much, by half again, over six hours is a leak
POOL_LEAK_MIN_GROWTH = 200 * 1024 ** 2
POOL_HISTORY_KEY = "host_pool_history"     # state: {tag: [[ts, bytes], ...]}, hourly, a week
POOL_LEAKS_KEY = "host_pool_leaks"         # state: [[tag, first bytes, last bytes, span s], ...]
POOL_OWNERS_KEY = "host_pool_owners"       # state: {"ts": when, "owners": {tag: owner or None}}
POOL_BIG_SHARE = 0.25                      # one tag holding this much of the pool is named even before it's seen growing
SYSTEM_HANDLES_WARN = 1_000_000


# virtual machines' memory processes: they grow as the guest fills its own file cache, by
# design - growth there isn't a leak in a Windows program
NOT_LEAKS = {"vmmemwsl", "vmmem", "vmwp"}  # matched against the lower-cased program name


def leaks(history, min_growth=LEAK_MIN_GROWTH, min_ratio=LEAK_MIN_RATIO, min_span_s=LEAK_MIN_SPAN_S):
    """history: {name: [(ts, bytes)...] in time order} -> [(name, start bytes, now bytes)] for
    programs (or, with smaller limits, kernel pool tags) whose memory only climbs: a leak, or
    at least worth a restart."""
    out = []
    for name, pts in history.items():
        if name.lower() in NOT_LEAKS:
            continue
        if len(pts) < 4 or pts[-1][0] - pts[0][0] < min_span_s:
            continue
        first, last = pts[0][1], pts[-1][1]
        if last - first < min_growth or last < first * (1 + min_ratio):
            continue
        # mostly rising: never fell back more than a tenth of what it had gained so far
        peak, steady = first, True
        for _, v in pts:
            if v < peak - 0.1 * (peak - first) - 64 * 1024 ** 2:
                steady = False
                break
            peak = max(peak, v)
        if steady:
            out.append((name, first, last))
    return sorted(out, key=lambda x: -(x[2] - x[1]))


def _gb(b):
    return f"{b / GB:.1f} GB"


def owner_name(o):
    """'Acme Shield filter driver (acmeflt.sys)' from tag_owners()' answer."""
    what = o.get("description") or o.get("product") or "a driver"
    if o.get("company") and o["company"].lower() not in what.lower():
        what = f"{o['company']} {what}"
    return f"{what} ({o['file']})"


def pool_cause(pool):
    """The sentence that names who holds the non-paged pool, or None. pool: {"leaks": [(tag,
    first, last, span_s)], "top": [(tag, bytes)], "owners": {tag: owner or None}, "total": bytes}."""
    if not pool:
        return None
    owners = pool.get("owners") or {}
    for tag, first, last, span in pool.get("leaks") or []:
        o = owners.get(tag)
        if o:
            per_day = (last - first) / span * 86400 if span else 0
            maker = o.get("company") or "its maker"
            return (f"It's {owner_name(o)}: its memory (tag {tag}) has grown from {_gb(first)} to {_gb(last)}, about "
                    f"{_mb(per_day)} a day, and never shrinks - a driver leak. Updating {o.get('product') or 'that software'} "
                    f"(or reporting it to {maker}) fixes it; restarting Windows clears it for now.")
    top = pool.get("top") or []
    total = pool.get("total") or 0
    if top and total:
        tag, size = top[0]
        o = owners.get(tag)
        if o and size >= POOL_BIG_SHARE * total:
            return (f"The largest part, {_gb(size)}, belongs to {owner_name(o)} (tag {tag}); if it keeps growing, "
                    "that driver is leaking.")
    return None


def _mb(b):
    return f"{b / 1024 ** 2:,.0f} MB"


def warnings(s, leaking=(), procs=(), pool=None):
    """Plain-language findings for a sample, worst first: [(level, text)].
    procs: [(name, bytes, count, handles, most handles in one process)] from processes().
    pool: who holds the non-paged pool (see pool_cause), when known."""
    out = []
    if not s:
        return out
    handle_leak = False
    for name, _, count, _, one in procs:
        if one >= PROCESS_HANDLES_WARN:  # a single process: a sum over many would mislead
            handle_leak = True
            who = name if count == 1 else f"One {name} process"
            out.append(("bad", f"{who} holds {one:,} handles (open references to system objects). That many "
                               "is a leak: each one uses kernel memory and the whole machine slows. "
                               "Restarting it (or Windows) releases them."))
    if (s.get("handles") or 0) >= SYSTEM_HANDLES_WARN and not handle_leak:
        out.append(("warn", f"{s['handles']:,} handles open across the system - far more than usual."))
    gb = _gb
    if s.get("commit_limit"):
        share = s["commit"] / s["commit_limit"]
        if share >= COMMIT_WARN:
            out.append(("bad" if share >= COMMIT_BAD else "warn",
                        f"Programs have reserved {gb(s['commit'])} of the {gb(s['commit_limit'])} Windows allows "
                        f"({share:.0%}). Near the limit the machine slows and programs fail, even with RAM free."))
    if s.get("mem_total") and s["mem_avail"] / s["mem_total"] < AVAIL_WARN:
        out.append(("warn", f"Only {gb(s['mem_avail'])} of {gb(s['mem_total'])} memory available."))
    if (s.get("pool_nonpaged") or 0) >= NONPAGED_WARN:
        cause = ("Likely the handle leak above." if handle_leak
                 else pool_cause(pool) or "Often a driver leaking over a long uptime - a restart clears it.")
        out.append(("warn", f"Windows kernel memory (non-paged pool) is {gb(s['pool_nonpaged'])}; usually well "
                            f"under 1 GB. {cause}"))
    for name, first, last in leaking:
        out.append(("warn", f"{name} has grown from {gb(first)} to {gb(last)} of reserved memory and keeps "
                            "climbing - likely a leak; restarting it gives the memory back."))
    if (s.get("uptime_s") or 0) >= UPTIME_NOTE_S and out:
        out.append(("info", f"Up for {s['uptime_s'] // 86400} days without a restart."))
    return out
