import json
from collections import Counter, defaultdict
from pathlib import Path

gates = json.loads(Path("xor_circuit.json").read_text())

def norm(cell):
    """
    JSON turns tuples into lists. Normalise:
      ["M", 3141, null] -> ("M", 3141)
      ["STK", 322, null] -> ("STK", 322)
      ["UNK", 123, "x8"] -> ("UNK:x8", 123)
    """
    ns = cell[0]
    off = cell[1]
    extra = cell[2] if len(cell) > 2 else None

    if ns == "UNK":
        ns = f"UNK:{extra}"

    return (ns, off)

reads = Counter()
writes = Counter()
read_before_write = []

written = set()

for i, g in enumerate(gates):
    a = norm(g["in_a"])
    b = norm(g["in_b"])
    out = norm(g["out"])

    for src in (a, b):
        reads[src] += 1
        if src not in written:
            read_before_write.append((i, src, out))

    writes[out] += 1
    written.add(out)

print("[+] gates:", len(gates))

print("\n[+] Read namespaces:")
print(Counter(ns for ns, off in reads))

print("\n[+] Write namespaces:")
print(Counter(ns for ns, off in writes))

print("\n[+] Unique cells read:", len(reads))
print("[+] Unique cells written:", len(writes))
print("[+] Read-before-write count:", len(read_before_write))

print("\n[+] First 80 read-before-write cells:")
for i, src, out in read_before_write[:80]:
    print(f"gate {i}: read {src} before write, output {out}")

print("\n[+] Most-written cells:")
for cell, count in writes.most_common(20):
    print(cell, count)

print("\n[+] Final 30 gates:")
for g in gates[-30:]:
    print(f"{norm(g['out'])} = {norm(g['in_a'])} XOR {norm(g['in_b'])}")
