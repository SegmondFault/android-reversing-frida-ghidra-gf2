import json
import os
from pathlib import Path

GATES_FILE = "xor_circuit.json"
TARGET = os.environ.get("TARGET", "STK:322")
# Real input mapping from setup code:
# input[i] is copied into B18[0xc85 - i]
INPUT_CELLS = [("B18", 0xc85 - i) for i in range(64)]

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

def load_seeds():
    seeds = {}
    for path in Path(".").glob("buf_B*.bin"):
        ns = path.stem.replace("buf_", "")
        seeds[ns] = path.read_bytes()
    return seeds

gates = json.loads(Path(GATES_FILE).read_text())
seeds = load_seeds()

# cell -> (mask, const)
# mask is a 64-bit int. Bit i means input bit i participates.
cells = {}

def seed_cell(cell):
    ns, off = cell
    if ns in seeds and off < len(seeds[ns]):
        return (0, seeds[ns][off] & 1)
    return (0, 0)

def get_cell(cell):
    if cell not in cells:
        cells[cell] = seed_cell(cell)
    return cells[cell]

# Install symbolic input variables.
for i, cell in enumerate(INPUT_CELLS):
    cells[cell] = (1 << i, 0)

print("[+] gates:", len(gates))
print("[+] loaded buffer namespaces:", sorted(seeds.keys()))
print("[+] input cells:", len(INPUT_CELLS))
print("[+] first/last input cells:", INPUT_CELLS[0], INPUT_CELLS[-1])

# Replay XOR circuit linearly.
for i, g in enumerate(gates, 1):
    ma, ca = get_cell(norm(g["in_a"]))
    mb, cb = get_cell(norm(g["in_b"]))
    out = norm(g["out"])
    cells[out] = (ma ^ mb, ca ^ cb)

    if i % 25000 == 0:
        print(f"[+] replayed {i}/{len(gates)}")

target = parse_target(TARGET)
mask, const = get_cell(target)

print("[+] target:", target)
print("[+] target equation:")
print("    mask =", hex(mask))
print("    const =", const)
print("    popcount(mask) =", mask.bit_count())

# We need: parity(mask & password_bits) XOR const == 1
# If mask != 0, choose one variable in mask to satisfy it and set rest to 0.
if mask == 0:
    print("[+] target is constant:", const)
    if const == 1:
        password = "0" * 64
        print("[+] any password satisfies this target under current model")
        print(password)
        raise SystemExit(0)
    else:
        print("[-] impossible for this target under current model")
        raise SystemExit(1)

needed = const ^ 1  # parity must equal needed
bits = [0] * 64

# Set the lowest participating bit to needed, all others 0.
idx = (mask & -mask).bit_length() - 1
bits[idx] = needed

password = "".join(str(b) for b in bits)

print("[+] candidate password bits:")
print(password)
print("[+] grouped:")
print(" ".join(password[i:i+8] for i in range(0, 64, 8)))

# Verify equation
parity = ((sum(bits[i] for i in range(64) if (mask >> i) & 1)) & 1)
print("[+] verifies target:", parity ^ const)
