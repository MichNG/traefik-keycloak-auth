#!/usr/bin/env python3
"""Turns the chaos probe log into a per-scenario report.

The probe writes "<seconds> <status> <latency>" and the driver writes
"MARK BEGIN <scenario>" / "MARK <scenario>" separators, so every scenario is the
window between two marks.
"""
import sys
from collections import Counter

path = sys.argv[1] if len(sys.argv) > 1 else "docker/chaos-runtime/probe.log"

scenarios = []           # (name, [(t, status, latency)])
current = None
raw = []
for line in open(path, encoding="utf-8", errors="replace"):
    line = line.strip()
    if not line:
        continue
    if line.startswith("MARK"):
        parts = line.split()
        name = " ".join(parts[2:]) if len(parts) > 2 else "?"
        current = (name, [])
        scenarios.append(current)
        continue
    fields = line.split()
    if len(fields) != 3:
        continue
    t, status, latency = fields
    raw.append((int(t), status, float(latency)))
    if current is not None:
        current[1].append((int(t), status, float(latency)))

if not scenarios:
    print("no scenarios found in the probe log")
    sys.exit(1)

def pct(values, p):
    if not values:
        return 0.0
    values = sorted(values)
    idx = min(len(values) - 1, int(round((p / 100.0) * (len(values) - 1))))
    return values[idx]

print(f"{'scenario':52} {'reqs':>5} {'200':>5} {'302':>4} {'5xx':>4} {'err':>4} {'p95 ms':>7} {'max ms':>7} {'streak':>6} {'recovery':>9}")
print("-" * 116)

for name, samples in scenarios:
    if not samples:
        print(f"{name[:52]:52} {'-':>5}")
        continue
    statuses = Counter(s for _, s, _ in samples)
    lat = [l * 1000 for _, _, l in samples]
    codes = [s for _, s, _ in samples]
    fivexx = sum(v for k, v in statuses.items() if k.startswith("5"))
    err = statuses.get("000", 0)
    # longest streak of consecutive non-200 answers
    streak = best = 0
    for c in codes:
        if c == "200":
            streak = 0
        else:
            streak += 1
            best = max(best, streak)
    # recovery: seconds between the end of the streak and the first 200 after it
    recovery = "-"
    idx = None
    for i, c in enumerate(codes):
        if c != "200" and i + 1 <= len(codes):
            idx = i
    if idx is not None:
        for j in range(idx, len(codes)):
            if codes[j] == "200":
                recovery = f"{samples[j][0] - samples[idx][0]}s"
                break
        if recovery == "-":
            recovery = "не восстановился"
    print(f"{name[:52]:52} {len(samples):5} {statuses.get('200', 0):5} {statuses.get('302', 0):4} "
          f"{fivexx:4} {err:4} {pct(lat, 95):7.0f} {max(lat) if lat else 0:7.0f} {best:6} {recovery:>9}")

print()
print("Легенда: 200 — сессия прочитана из Redis Sentinel (и продлена, sliding); "
      "302 — сессия потеряна, браузер уходит на повторный логин; "
      "5xx — отказ закрытый (503) либо ошибка плагина; "
      "err — соединение не установлено (000); streak — самая длинная серия не-200.")

# statuses of the whole run, for the summary
allstatus = Counter(s for _, s, _ in raw)
total = sum(allstatus.values())
print()
print(f"Весь прогон: {total} запросов, "
      f"200: {allstatus.get('200', 0)} ({100.0 * allstatus.get('200', 0) / max(total, 1):.1f}%), "
      f"302: {allstatus.get('302', 0)}, "
      f"5xx: {sum(v for k, v in allstatus.items() if k.startswith('5'))}, "
      f"нет соединения: {allstatus.get('000', 0)}")
