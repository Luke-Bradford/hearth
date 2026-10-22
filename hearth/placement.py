"""Placing devices the mesh doesn't list (#38, step 1, part 4).

In access-point mode, Decos leave some wired devices behind a switch out of their client
lists. Ping timing can still say where such a device hangs: a device can't reply faster than
the unit it hangs off, and usually replies a little slower (its own last hop). So compare
its latency floor - the 5th percentile of its replies over the last 6 hours - with each mesh
unit's own floor, and place it only when one unit clearly fits. Floors are relative to the
machine running Hearth. Pure functions: the caller supplies the floors.
"""
PLACE_BELOW_TOL_MS = 0.5   # a unit may be this much slower than the device and still be its unit
PLACE_MARGIN_MS = 2.0      # the device may be this much slower than its unit (its own last hop)
MIN_SAMPLES = 120          # replies needed to trust a floor (ten minutes of 5-second pings)
FLOOR_WINDOW_S = 6 * 3600  # the floor is taken over this long
FLOOR_REFRESH_S = 300      # floors are worked out again this often: a 6-hour statistic barely moves in 5 minutes
FLOOR_PCT = 0.05           # the floor is this percentile of the replies (a low one, not the minimum: one lucky reply)


def _r(placement, node, why):
    return {"placement": placement, "node": node, "why": why}


def place(floor, samples, unit_floors, hearth_unit, is_local, names=None):
    """{placement, node, why} for one device the mesh doesn't list (see the module docstring).
    unit_floors: {unit_mac: (floor_ms, name)} for units with a floor; names: {unit_mac: name}
    for every unit (Hearth's own unit may have no floor of its own). Differences are compared
    rounded to 0.01 ms, the precision the floors are given in."""
    names = names or {}
    if floor is None or samples < MIN_SAMPLES:
        return _r("unknown", None, "not enough replies to place it by timing")
    if not unit_floors:
        return _r("unknown", None, "no mesh unit has been measured to compare with")
    lowest = min(f for f, _ in unit_floors.values())
    if is_local or round(lowest - floor, 2) > PLACE_BELOW_TOL_MS:
        if hearth_unit is None:
            return _r("unknown", None, "replies like a device next to this computer, but the mesh doesn't "
                                       "list this computer, so its unit is unknown")
        name = names.get(hearth_unit) or unit_floors.get(hearth_unit, (None, hearth_unit))[1]
        return _r("timing", hearth_unit, f"on the same switch or segment as this computer (on {name}); "
                                         f"the mesh doesn't list it")
    cands = sorted(((f, mac, name) for mac, (f, name) in unit_floors.items()
                    if round(f - floor, 2) <= PLACE_BELOW_TOL_MS), reverse=True)
    if not cands:
        return _r("unknown", None, "replies faster than any mesh unit it could hang off")
    f, mac, name = cands[0]
    if round(floor - f, 2) > PLACE_MARGIN_MS:
        return _r("unknown", None, f"replies slower than every mesh unit by more than {PLACE_MARGIN_MS:g} ms")
    if len(cands) > 1 and round(floor - cands[1][0], 2) <= PLACE_MARGIN_MS:
        return _r("unknown", None, f"could hang off {name} or {cands[1][2]}: their reply times are too close")
    return _r("timing", mac, f"replies like the {name} unit ({floor:.2f} ms vs {f:.2f} ms); the mesh doesn't list it")
