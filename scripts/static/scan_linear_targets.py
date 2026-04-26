import json
from pathlib import Path
from collections import defaultdict

GATES_FILE = "xor_circuit.json"
INPUT_CELLS = [("B18", 0xc85 - i) for i in range(64)]

def norm(cell):
    ns = cell[0]
    off = cell[1]
    extra = cell[2] if len(cell) > 2 else None
    if ns == "UNK":
        ns = f"UNK:{extra}"
    return (ns, off)

def load_seeds():
    seeds = {}
    for path in Path(".").glob("buf_B*.bin"):
        ns = path.stem.replace("buf_", "")
        seeds[ns] = path.read_bytes()
    return seeds

def seed_cell(cell, seeds):
    ns, off = cell
    if ns in seeds and off < len(seeds[ns]):
        return (0, seeds[ns][off] & 1)
    return (0, 0)

gates = json.loads(Path(GATES_FILE).read_text())
seeds = load_seeds()
cells = {}

def get_cell(cell):
    if cell not in cells:
        cells[cell] = seed_cell(cell, seeds)
    return cells[cell]

for i, cell in enumerate(INPUT_CELLS):
    cells[cell] = (1 << i, 0)

for g in gates:
    ma, ca = get_cell(norm(g["in_a"]))
    mb, cb = get_cell(norm(g["in_b"]))
    out = norm(g["out"])
    cells[out] = (ma ^ mb, ca ^ cb)

interesting = []
for cell, (mask, const) in cells.items():
    if mask != 0:
        interesting.append((mask.bit_count(), cell, mask, const))

interesting.sort(reverse=True)

print("[+] symbolic-dependent cells:", len(interesting))
print("[+] top 80 by popcount:")
for pc, cell, mask, const in interesting[:80]:
    print(f"{cell} popcount={pc} const={const} mask={hex(mask)}")

print("\n[+] final-ish STK cells 300..430:")
for off in range(300, 431):
    cell = ("STK", off)
    if cell in cells:
        mask, const = cells[cell]
        if mask:
            print(f"{cell} popcount={mask.bit_count()} const={const} mask={hex(mask)}")
