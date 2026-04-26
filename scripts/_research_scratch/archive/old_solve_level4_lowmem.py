import time
import gc
import resource
import angr
import claripy

LIB_PATH = "level4_extract/lib/arm64-v8a/libnative_level_4.so"

BASE_ADDR = 0x100000
VALIDATOR_ADDR = 0x1200c8
XOR_REAL_ADDR = 0x120000
XOR_PLT_ADDR = 0x6862f0
BUF_ADDR = 0x90000000
RET_ADDR = 0x80000000

MAX_STEPS = 2_000_000
REPORT_EVERY = 20_000
SIMPLIFY_EVERY = 100_000

xor_hits = 0

class XorBool(angr.SimProcedure):
    def run(self, a, b):
        global xor_hits
        xor_hits += 1
        return (a & 1) ^ (b & 1)

def mem_gb():
    # macOS reports ru_maxrss in bytes
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / (1024 ** 3)

proj = angr.Project(
    LIB_PATH,
    auto_load_libs=False,
    main_opts={"base_addr": BASE_ADDR},
)

# Hook both real symbol and PLT trampoline.
proj.hook_symbol("_Z1abb", XorBool())
proj.hook(XOR_REAL_ADDR, XorBool(), replace=True)
proj.hook(XOR_PLT_ADDR, XorBool(), replace=True)

state = proj.factory.call_state(
    VALIDATOR_ADDR,
    BUF_ADDR,
    ret_addr=RET_ADDR,
    prototype="char validator(char *)",
)

# Avoid pointless tracking/history bloat.
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

state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
state.options.add(angr.options.LAZY_SOLVES)

with open("bpb_seed.bin", "rb") as f:
    seed = f.read()

print(f"[+] Loaded real _Z1bPb seed buffer: {len(seed)} bytes")
state.memory.store(BUF_ADDR, seed)

bits = []
for i in range(64):
    b = claripy.BVS(f"b{i}", 8)
    bits.append(b)
    state.memory.store(BUF_ADDR + i, b)
    state.solver.add((b == 0) | (b == 1))

# No veritesting here. This is a single-path giant circuit, so veritesting may add overhead.
simgr = proj.factory.simulation_manager(state)
found = None

start = time.time()
last = start
last_xor = 0

def is_ret_success(s):
    return s.addr == RET_ADDR and s.solver.satisfiable(extra_constraints=[(s.regs.x0 & 1) == 1])

def is_ret_failure(s):
    return s.addr == RET_ADDR and s.solver.satisfiable(extra_constraints=[(s.regs.x0 & 1) == 0])

print(f"[+] Loaded: {LIB_PATH}")
print(f"[+] Validator: {hex(VALIDATOR_ADDR)}")
print(f"[+] XOR helper hooked at symbol/real/PLT")
print("[+] Starting lower-memory symbolic execution")

try:
    for step in range(1, MAX_STEPS + 1):
        simgr.step()

        if simgr.errored:
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
            with open("level4_return_state.pkl", "wb") as f:
                pickle.dump({"state": s, "bits": bits}, f)
            print("[+] Saved return state+bits to level4_return_state.pkl")

            with open("level4_constraints.smt2", "w") as f:
                f.write(s.solver.sexpr())
            print("[+] Saved solver constraints to level4_constraints.smt2")

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

print(f"[+] Finished at t={time.time()-start:.1f}s xor_hits={xor_hits} mem_high={mem_gb():.2f}GB")

if simgr.errored:
    print("[!] Errored states:")
    for i, e in enumerate(simgr.errored[:3]):
        print(f"--- error {i} ---")
        print("state addr:", hex(e.state.addr) if e.state is not None else None)
        print("error:", repr(e.error))

if found is None:
    print("[-] No solution found in this run")
    raise SystemExit(1)

password = "".join(str(found.solver.eval(b)) for b in bits)
print("[+] Password:")
print(password)
