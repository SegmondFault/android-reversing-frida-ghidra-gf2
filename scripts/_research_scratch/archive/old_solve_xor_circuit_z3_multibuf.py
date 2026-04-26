import json
import os
from pathlib import Path
from z3 import Solver, Bool, BoolVal, Xor, sat

GATES_FILE = "xor_circuit.json"

# Try final stack outputs first. Override with:
#   TARGET=STK:322 python solve_xor_circuit_z3_multibuf.py
TARGET = os.environ.get("TARGET", "STK:322")

# Boolish diff from zero/one dump. These were in the old single-buffer view.
# Now likely correspond to B50 unless we later prove otherwise.
INPUT_NS = os.environ.get("INPUT_NS", "B50")
INPUT_OFFSETS = [0x4cf] + list(range(0xc47, 0xc86))

def parse_target(s):
    ns, off = s.split(":")
    return (ns, int(off, 0))

def norm(cell):
    ns = cell[0]
    off = cell[1]
    extra = cell[2] if len(cell) > 2 else None
    if ns == "UNK":
        ns = f"UNK:{extra}"
    return (ns, off)

def byte_to_bool(x):
    return bool(x & 1)

def xor_val(a, b):
    # Keep concrete values as Python bools.
    if isinstance(a, bool) and isinstance(b, bool):
        return a ^ b
    return Xor(a, b)

def to_z3(v):
    return BoolVal(v) if isinstance(v, bool) else v

def load_buffer_seeds():
    seeds = {}
    for path in Path(".").glob("buf_B*.bin"):
        ns = path.stem.replace("buf_", "")   # buf_B50.bin -> B50
        seeds[ns] = path.read_bytes()
    return seeds

gates = json.loads(Path(GATES_FILE).read_text())
seeds = load_buffer_seeds()

print("[+] loaded buffer namespaces:", sorted(seeds.keys()))
print("[+] count:", len(seeds))

solver = Solver()
cells = {}

def get_cell(cell):
    ns, off = cell

    if cell in cells:
        return cells[cell]

    if ns in seeds and off < len(seeds[ns]):
        cells[cell] = byte_to_bool(seeds[ns][off])
    else:
        # Stack cells and genuinely absent cells default false unless written.
        cells[cell] = BoolVal(False)

    return cells[cell]

# Symbolic password bits.
bits = []
for idx, off in enumerate(INPUT_OFFSETS):
    b = Bool(f"b{idx}")
    bits.append(b)
    cells[(INPUT_NS, off)] = b

print(f"[+] symbolic input namespace: {INPUT_NS}")
print(f"[+] symbolic input bits: {len(bits)}")
print(f"[+] input offsets: {hex(INPUT_OFFSETS[0])}, {hex(INPUT_OFFSETS[1])}..{hex(INPUT_OFFSETS[-1])}")

# Replay full extracted XOR circuit.
for i, g in enumerate(gates, 1):
    a = get_cell(norm(g["in_a"]))
    b = get_cell(norm(g["in_b"]))
    out = norm(g["out"])
    cells[out] = xor_val(a, b)

    if i % 25000 == 0:
        print(f"[+] replayed {i}/{len(gates)} gates")

target_cell = parse_target(TARGET)
target_expr = to_z3(get_cell(target_cell))

print(f"[+] gates replayed: {len(gates)}")
print(f"[+] target: {target_cell}")
print("[+] asking solver for target == true")

solver.add(target_expr == True)
res = solver.check()

print("[+] solver result:", res)

if res != sat:
    raise SystemExit(1)

model = solver.model()
password = "".join("1" if model.evaluate(b, model_completion=True) else "0" for b in bits)

print("[+] candidate password bits:")
print(password)
print("[+] grouped:")
print(" ".join(password[i:i+8] for i in range(0, len(password), 8)))
print("[+] target value:", model.evaluate(target_expr, model_completion=True))
