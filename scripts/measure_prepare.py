#!/usr/bin/env python3
"""measure_prepare.py — how long does prepare() take & how much guest RAM maps?"""
import sys, time, os
sys.path.insert(0, "/home/z/my-project/scripts")
import fn35_loader as L

t0 = time.time()
loader = L.FNLoader(
    "/home/z/my-project/fn35/extracted/Payload/FortniteClient.app/FortniteClient",
    "/home/z/my-project/fn35/sandbox", budget=1.0, live_log=False)
t1 = time.time()
loader.prepare()
t2 = time.time()

regions = [(r[0], r[1]) for r in loader.uc.mem_regions()]
total = sum(e - b + 1 for b, e in regions)
rss = int(open("/proc/self/status").read().split("VmRSS:")[1].split()[0])

print("init      : %.2fs" % (t1 - t0))
print("prepare   : %.2fs" % (t2 - t1))
print("regions   : %d" % len(regions))
print("guest RAM : %.1f MB" % (total / 1e6))
print("host RSS  : %.1f MB" % (rss / 1024))
print("--- region map (top 10 by size) ---")
for b, e in sorted(regions, key=lambda r: -(r[1] - r[0]))[:10]:
    print("  0x%012x-0x%012x  %8.2f MB" % (b, e + 1, (e - b + 1) / 1e6))

# time a full mem_read of everything (worst-case save cost)
t3 = time.time()
n = 0
for b, e in regions:
    n += len(loader.uc.mem_read(b, e - b + 1))
t4 = time.time()
print("mem_read all: %.2fs (%.1f MB -> %.0f MB/s)" % (t4 - t3, n / 1e6,
                                                       n / 1e6 / (t4 - t3)))
