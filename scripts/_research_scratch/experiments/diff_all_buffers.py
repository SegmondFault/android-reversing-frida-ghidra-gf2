from pathlib import Path
from collections import defaultdict

zdir = Path("bufs_zero")
odir = Path("bufs_ones")

diffs = []
boolish = []

for zp in sorted(zdir.glob("buf_B*.bin")):
    op = odir / zp.name
    if not op.exists():
        continue

    ns = zp.stem.replace("buf_", "")
    z = zp.read_bytes()
    o = op.read_bytes()

    for i, (a, b) in enumerate(zip(z, o)):
        if a != b:
            diffs.append((ns, i, a, b))
            if {a, b} <= {0, 1}:
                boolish.append((ns, i, a, b))

print("[+] total diffs:", len(diffs))
print("[+] boolish diffs:", len(boolish))

print("\n[+] boolish diffs:")
for ns, off, a, b in boolish:
    print(f"{ns}:{hex(off)} {a}->{b}")

print("\n[+] count by namespace:")
counts = defaultdict(int)
for ns, off, a, b in boolish:
    counts[ns] += 1
for ns, c in sorted(counts.items()):
    print(ns, c)
