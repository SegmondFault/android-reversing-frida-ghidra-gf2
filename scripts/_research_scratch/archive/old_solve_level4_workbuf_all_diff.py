import time
import gc
import resource
import angr
import claripy
from pathlib import Path

LIB_PATH = "level4_extract/lib/arm64-v8a/libnative_level_4.so"

BASE_ADDR = 0x100000
# Start at the first XOR region, not the start of _Z1bPb setup.
VALIDATOR_ADDR = 0x1206b0
XOR_REAL_ADDR = 0x120000
XOR_PLT_ADDR = 0x6862f0
BUF_ADDR = 0x90000000
RET_ADDR = 0x80000000

MAX_STEPS = 2_000_000
REPORT_EVERY = 50_000
SIMPLIFY_EVERY = 100_000

xor_hits = 0

class XorBool(angr.SimProcedure):
    def run(self, a, b):
        global xor_hits
        xor_hits += 1
        return (a & 1) ^ (b & 1)

def mem_gb():
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / (1024 ** 3)

zero = Path("workbuf_zero.bin").read_bytes()
ones = Path("workbuf_ones.bin").read_bytes()

diffs = [i for i, (a, b) in enumerate(zip(zero, ones)) if a != b]

# The likely direct user bit locations: 63-byte run plus one nearby singleton.
input_offsets = diffs

print(f"[+] total diff bytes zero-vs-ones: {len(diffs)}")
print(f"[+] DIAGNOSTIC: using ALL diff offsets as symbolic: {len(input_offsets)} bytes")
print(f"[+] first/last input offsets: {hex(input_offsets[0])} .. {hex(input_offsets[-1])}")

proj = angr.Project(
    LIB_PATH,
    auto_load_libs=False,
    main_opts={"base_addr": BASE_ADDR},
)

proj.hook_symbol("_Z1abb", XorBool())
proj.hook(XOR_REAL_ADDR, XorBool(), replace=True)
proj.hook(XOR_PLT_ADDR, XorBool(), replace=True)

state = proj.factory.blank_state(addr=VALIDATOR_ADDR)

state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
state.options.add(angr.options.LAZY_SOLVES)

for opt_name in [
    "TRACK_MEMORY_ACTIONS",
    "TRACK_REGISTER_ACTIONS",
    "TRACK_JMP_ACTIONS",
    "TRACK_CONSTRAINT_ACTIONS",
    "AST_DEPS",
    "ACTION_DEPS",
]:
    opt = getattr(angr.options, opt_name, None)
    if opt is not None and opt in state.options:
        state.options.discard(opt)

# Seed the real work buffer.
state.memory.store(BUF_ADDR, zero)

# Set registers to mimic the first XOR region.
# At 0x1206b0 the code expects x8 to be the work-buffer base.
state.regs.x8 = BUF_ADDR
state.regs.sp = 0xA0000000
state.regs.x29 = 0xA0001000
state.regs.x30 = RET_ADDR  # link register

bits = []
for idx, off in enumerate(input_offsets):
    b = claripy.BVS(f"b{idx}", 8)
    bits.append(b)
    state.memory.store(BUF_ADDR + off, b)
    state.solver.add((b == 0) | (b == 1))

simgr = proj.factory.simulation_manager(state)
found = None

start = time.time()
last = start
last_xor = 0

print(f"[+] Loaded: {LIB_PATH}")
print(f"[+] Circuit start: {hex(VALIDATOR_ADDR)}")
print(f"[+] Starting workbuf symbolic execution")

try:
    for step in range(1, MAX_STEPS + 1):
        simgr.step()

        if simgr.errored:
            e = simgr.errored[0]
            if e.state is not None and e.state.addr == 0:
                print("[+] Hit address 0x0 after completing circuit; treating as synthetic return")
                s = e.state
                ret_bit = s.memory.load(s.regs.x29 - 0x11, 1) & 1

                print("[+] Checking [x29 - 0x11] success byte satisfiability...")
                can_true = s.solver.satisfiable(extra_constraints=[ret_bit == 1])
                can_false = s.solver.satisfiable(extra_constraints=[ret_bit == 0])

                print(f"[+] ret_bit can be true: {can_true}")
                print(f"[+] ret_bit can be false: {can_false}")

                print("[+] Register low-bit satisfiability at synthetic return:")
                for reg in ["x0","x1","x2","x3","x4","x5","x6","x7","x8","x9","x10","x11","x12","x13","x14","x15"]:
                    rv = getattr(s.regs, reg) & 1
                    rt = s.solver.satisfiable(extra_constraints=[rv == 1])
                    rf = s.solver.satisfiable(extra_constraints=[rv == 0])
                    print(f"    {reg} & 1: can_true={rt} can_false={rf}")

                import pickle
                with open("workbuf_end_state.pkl", "wb") as f:
                    pickle.dump({"state": s, "bits": bits}, f)
                print("[+] Saved end state to workbuf_end_state.pkl")

                with open("workbuf_constraints.smt2", "w") as f:
                    f.write(s.solver.sexpr())
                print("[+] Saved constraints to workbuf_constraints.smt2")

                if can_true:
                    s.solver.add(ret_bit == 1)
                    found = s
                break

            print("[!] Error appeared, stopping")
            break

        if not simgr.active:
            print("[-] No active states left")
            break

        s = simgr.active[0]

        if s.addr == RET_ADDR:
            print("[+] Reached return sentinel")
            ret_bit = s.regs.x0 & 1

            print("[+] Checking return bit satisfiability...")
            can_true = s.solver.satisfiable(extra_constraints=[ret_bit == 1])
            can_false = s.solver.satisfiable(extra_constraints=[ret_bit == 0])

            print(f"[+] ret_bit can be true: {can_true}")
            print(f"[+] ret_bit can be false: {can_false}")

            import pickle
            with open("workbuf_end_state.pkl", "wb") as f:
                pickle.dump({"state": s, "bits": bits}, f)
            print("[+] Saved end state to workbuf_end_state.pkl")

            with open("workbuf_constraints.smt2", "w") as f:
                f.write(s.solver.sexpr())
            print("[+] Saved constraints to workbuf_constraints.smt2")

            if can_true:
                s.solver.add(ret_bit == 1)
                found = s
            break

        if step % SIMPLIFY_EVERY == 0:
            print(f"[*] Simplifying solver at step {step}...")
            s.solver.simplify()
            gc.collect()

        if step % REPORT_EVERY == 0:
            now = time.time()
            rate = REPORT_EVERY / max(now - last, 0.001)
            xor_rate = (xor_hits - last_xor) / max(now - last, 0.001)
            last = now
            last_xor = xor_hits
            print(
                f"[t={now-start:.1f}s step={step} rate={rate:.1f}/s "
                f"xor_hits={xor_hits} xor/s={xor_rate:.1f} "
                f"addr={hex(s.addr)} mem_high={mem_gb():.2f}GB]"
            )

except KeyboardInterrupt:
    print("\n[!] Interrupted")

print(f"[+] Finished t={time.time()-start:.1f}s xor_hits={xor_hits} mem_high={mem_gb():.2f}GB")

if simgr.errored:
    for i, e in enumerate(simgr.errored[:3]):
        print(f"--- error {i} ---")
        print("state addr:", hex(e.state.addr) if e.state is not None else None)
        print("error:", repr(e.error))

if found is None:
    print("[-] No solution found")
    raise SystemExit(1)

password = "".join(str(found.solver.eval(b)) for b in bits)
print("[+] Candidate password:")
print(password)
