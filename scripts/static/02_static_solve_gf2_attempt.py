import json
from pathlib import Path

GATES_PATH = "xor_circuit.json"
SEED_DIR = Path("bufs_finalcheck")
ZERO_FINAL_PATH = SEED_DIR / "stack_zero_final.json"

INPUT_CELLS = [("B18", 0xc85 - i) for i in range(59)]






def load_zero_final_consts():
    import json
    if not ZERO_FINAL_PATH.exists():
        return {}
    raw = json.loads(ZERO_FINAL_PATH.read_text())
    out = {}
    for k, v in raw.items():
        if isinstance(v, int):
            out[("STK", int(k, 16))] = v & 1
    return out

def load_seed_cells(seed_dir=SEED_DIR):
    cells = {}

    # Seed dumped buffer cells as concrete constants.
    for path in seed_dir.glob("buf_B*.bin"):
        name = path.stem.replace("buf_", "")
        data = path.read_bytes()
        for i, b in enumerate(data):
            cells[(name, i)] = (0, b & 1)

    # Seed only intermediate stack cells.
    # Do NOT seed final output/check cells 0x142..0x160,
    # because the circuit must compute those symbolically.
    sf = seed_dir / "stack_seed.json"
    if sf.exists():
        import json
        stack = json.loads(sf.read_text())
        for k, v in stack.items():
            off = int(k, 16)
            if isinstance(v, int):
                cells[("STK", off)] = (0, v & 1)

    return cells





TARGET_ONE_CELLS = [
    ("STK", 0x15e), ("STK", 0x15d), ("STK", 0x15b), ("STK", 0x159),
    ("STK", 0x157), ("STK", 0x155), ("STK", 0x153), ("STK", 0x152),
    ("STK", 0x151), ("STK", 0x150), ("STK", 0x14f), ("STK", 0x14a),
    ("STK", 0x148), ("STK", 0x147), ("STK", 0x143), ("STK", 0x142),
]

TARGET_ZERO_CELLS = [
    ("STK", 0x15c), ("STK", 0x15a), ("STK", 0x158), ("STK", 0x156),
    ("STK", 0x154), ("STK", 0x14e), ("STK", 0x14d), ("STK", 0x14c),
    ("STK", 0x14b), ("STK", 0x149), ("STK", 0x146), ("STK", 0x145),
]

def norm(x):
    if isinstance(x, list):
        return tuple(x[:2])
    if isinstance(x, tuple):
        return tuple(x[:2])
    raise TypeError(x)

def load_seeds():
    cells = {}

    for path in SEED_DIR.glob("buf_B*.bin"):
        ns = path.stem.replace("buf_", "")
        data = path.read_bytes()
        for i, b in enumerate(data):
            cells[(ns, i)] = (0, b & 1)

    return cells

def get_cell(cells, cell):
    cell = norm(cell)
    if cell not in cells:
        cells[cell] = (0, 0)
    return cells[cell]

def xor_expr(a, b):
    return (a[0] ^ b[0], a[1] ^ b[1])

def solve_gf2(equations):
    rows = []
    for mask, rhs in equations:
        rows.append([mask, rhs])

    pivot_row = 0
    pivots = []

    for col in range(64):
        pivot = None
        for r in range(pivot_row, len(rows)):
            if (rows[r][0] >> col) & 1:
                pivot = r
                break

        if pivot is None:
            continue

        rows[pivot_row], rows[pivot] = rows[pivot], rows[pivot_row]
        pivots.append((pivot_row, col))

        for r in range(len(rows)):
            if r != pivot_row and ((rows[r][0] >> col) & 1):
                rows[r][0] ^= rows[pivot_row][0]
                rows[r][1] ^= rows[pivot_row][1]

        pivot_row += 1

    for mask, rhs in rows:
        if mask == 0 and rhs:
            return None

    solution = 0
    for r, col in pivots:
        if rows[r][1]:
            solution |= (1 << col)

    return solution

gates = json.loads(Path(GATES_PATH).read_text())
cells = load_seed_cells()
zero_final_consts = load_zero_final_consts()
print("[+] gates:", len(gates))
print("[+] buffers:", len({k[0] for k in cells}))
print("[+] input cells:", INPUT_CELLS[0], "..", INPUT_CELLS[-1])

# Overwrite the real zero-input dump with symbolic variables.
for i, cell in enumerate(INPUT_CELLS):
    cells[cell] = (1 << i, 0)

for i, g in enumerate(gates, 1):
    a = get_cell(cells, g["in_a"])
    b = get_cell(cells, g["in_b"])
    out = norm(g["out"])
    cells[out] = xor_expr(a, b)

    if i % 50000 == 0:
        print(f"[+] replayed {i}/{len(gates)}")

print("[+] target equations:")
equations = []

for cell in TARGET_ONE_CELLS:
    mask, const = cells[cell]
    const = zero_final_consts.get(cell, const)
    rhs = const ^ 1
    equations.append((mask, rhs))
    print(f"    {cell} == 1: mask={hex(mask)} pop={mask.bit_count()} const={const} => rhs={rhs}")

for cell in TARGET_ZERO_CELLS:
    mask, const = cells[cell]
    const = zero_final_consts.get(cell, const)
    rhs = const ^ 0
    equations.append((mask, rhs))
    print(f"    {cell} == 0: mask={hex(mask)} pop={mask.bit_count()} const={const} => rhs={rhs}")

solution = solve_gf2(equations)
if solution is None:
    print("[-] No solution")
    raise SystemExit(1)

bits = [(solution >> i) & 1 for i in range(64)]
password = "".join(str(b) for b in bits)

print("[+] candidate password:")
print(password)
print("[+] grouped:")
print(" ".join(password[i:i+8] for i in range(0, 64, 8)))

print("[+] verify equations:")
ok = True

for cell in TARGET_ONE_CELLS:
    mask, const = cells[cell]
    val = ((solution & mask).bit_count() & 1) ^ const
    print(f"    {cell} should=1 value={val}")
    ok &= val == 1

for cell in TARGET_ZERO_CELLS:
    mask, const = cells[cell]
    val = ((solution & mask).bit_count() & 1) ^ const
    print(f"    {cell} should=0 value={val}")
    ok &= val == 0

print("[+] all final checks satisfied:", ok)
