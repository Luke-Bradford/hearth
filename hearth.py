"""
Hearth - home network health monitor.

Finds your router, your devices and the route to your ISP by itself, works out which
devices sit behind which wireless link, pings everything, and blames each latency spike
on the link where it started. Pure Python standard library; no Administrator rights needed.

Usage:  python hearth.py            (dashboard at http://<this-pc>:8080)
"""
from hearth.main import main

if __name__ == "__main__":
    main()
