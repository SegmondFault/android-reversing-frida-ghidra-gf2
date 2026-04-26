import time
import angr
import claripy
from pathlib import Path

LIB_PATH = "level4_extract/lib/arm64-v8a/libnative_level_4.so"

BASE_ADDR = 0x100000
CIRCUIT_START = 0x1206b0
XOR_REAL_ADDR = 0x120000
XOR_PLT_ADDR = 0x6862f0
BUF_ADDR = 0x90000000

MODE = "ones"  # change to "ones" later

xor_hits = 0

class XorBool(angr.SimProcedure):
    def run(self, a, b):
        global xor_hits
        xor_hits += 1
        return (a & 1) ^ (b & 1)

seed_file = "workbuf_zero.bin" if MODE == "zero" else "workbuf_ones.bin"
seed = Path(seed_file).read_bytes()

# These were the 64-ish input-controlled bytes found by diffing zero/one buffers.
input_offsets = list(range(0xc47, 0xc86)) + [0xc87]

proj = angr.Project(
    LIB_PATH,
    auto_load_libs=False,
    main_opts={"base_addr": BASE_ADDR},
)

proj.hook_symbol("_Z1abb", XorBool())
proj.hook(XOR_REAL_ADDR, XorBool(), replace=True)
proj.hook(XOR_PLT_ADDR, XorBool(), replace=True)

state = proj.factory.blank_state(addr=CIRCUIT_START)

state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
state.options.add(angr.options.LAZY_SOLVES)

# Seed actual dumped work buffer.
state.memory.store(BUF_ADDR, seed)

# At this circuit point, x8 is the work-buffer base.
state.regs.x8 = BUF_ADDR
state.regs.sp = 0xA0000000
state.regs.x30 = 0

# Force the suspected input offsets concretely.
value = 0 if MODE == "zero" else 1
for off in input_offsets:
    state.memory.store(BUF_ADDR + off, claripy.BVV(value, 8))

simgr = proj.factory.simulation_manager(state)

start = time.time()

print(f"[+] Concrete replay mode: {MODE}")
print(f"[+] Seed file: {seed_file}")
print(f"[+] Circuit start: {hex(CIRCUIT_START)}")
print(f"[+] Input offsets: {len(input_offsets)}")

for step in range(1, 500000):
    simgr.step()

    if simgr.errored:
        e = simgr.errored[0]
        print("[+] Errored / ended")
        print("    state addr:", hex(e.state.addr) if e.state is not None else None)
        print("    error:", repr(e.error))

        if e.state is not None:
            ret = e.state.solver.eval(e.state.regs.x0 & 1)
            print("[+] x0 low bit:", ret)
            print("[+] xor_hits:", xor_hits)
            print("[+] elapsed:", round(time.time() - start, 2), "sec")
        break

    if not simgr.active:
        print("[-] No active states")
        break

    s = simgr.active[0]

    if step % 50000 == 0:
        print(f"[t={time.time()-start:.1f}s step={step} xor_hits={xor_hits} addr={hex(s.addr)}")

else:
    print("[-] Hit max steps without ending")
