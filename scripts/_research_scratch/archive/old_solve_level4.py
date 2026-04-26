import time
import angr
import claripy

LIB_PATH = "level4_extract/lib/arm64-v8a/libnative_level_4.so"

BASE_ADDR = 0x100000
VALIDATOR_ADDR = 0x1200c8
BUF_ADDR = 0x500000
RET_ADDR = 0x700000

MAX_STEPS = 2000000
REPORT_EVERY = 10000

xor_hits = 0

class XorBool(angr.SimProcedure):
    def run(self, a, b):
        global xor_hits
        xor_hits += 1
        return (a & 1) ^ (b & 1)

proj = angr.Project(
    LIB_PATH,
    auto_load_libs=False,
    main_opts={"base_addr": BASE_ADDR},
)

print("[+] Symbols / PLT guesses:")
sym = proj.loader.find_symbol("_Z1abb")
print("    find_symbol(_Z1abb):", sym, hex(sym.rebased_addr) if sym else None)

main = proj.loader.main_object
print("    main_object min/max:", hex(main.min_addr), hex(main.max_addr))

if hasattr(main, "plt"):
    for name, addr in main.plt.items():
        if "abb" in name or "_Z1a" in name:
            print("    PLT:", name, hex(addr))

# Best method: hook by symbol, lets CLE resolve the right call target.
proj.hook_symbol("_Z1abb", XorBool())

# Also hook likely addresses defensively.
for addr in [0x120000, 0x5862f0, 0x6862f0]:
    try:
        if proj.loader.find_object_containing(addr) is not None:
            proj.hook(addr, XorBool(), replace=True)
            print(f"[+] Also hooked {hex(addr)}")
    except Exception as e:
        print(f"[-] Could not hook {hex(addr)}: {e}")

state = proj.factory.call_state(
    VALIDATOR_ADDR,
    BUF_ADDR,
    ret_addr=RET_ADDR,
    prototype="char validator(char *)",
)

state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)

bits = []
for i in range(64):
    b = claripy.BVS(f"b{i}", 8)
    bits.append(b)
    state.memory.store(BUF_ADDR + i, b)
    state.solver.add((b == 0) | (b == 1))

simgr = proj.factory.simulation_manager(state, veritesting=True)
found_states = []

start = time.time()
last = start

def elapsed():
    return time.time() - start

def state_summary():
    return (
        f"active={len(simgr.active)} "
        f"found={len(found_states)} "
        f"deadended={len(simgr.deadended)} "
        f"errored={len(simgr.errored)} "
        f"xor_hits={xor_hits}"
    )

def is_success_state(s):
    if s.addr != RET_ADDR:
        return False
    return s.solver.satisfiable(extra_constraints=[s.regs.x0 == 1])

def is_bad_return(s):
    if s.addr != RET_ADDR:
        return False
    return s.solver.satisfiable(extra_constraints=[s.regs.x0 == 0])

print(f"[+] Loaded: {LIB_PATH}")
print(f"[+] Validator: {hex(VALIDATOR_ADDR)}")
print("[+] Starting symbolic execution")

try:
    for step in range(1, MAX_STEPS + 1):
        simgr.step()

        survivors = []
        for s in simgr.active:
            if is_success_state(s):
                found_states.append(s)
            elif is_bad_return(s):
                simgr.deadended.append(s)
            else:
                survivors.append(s)
        simgr.active = survivors

        now = time.time()
        if step % REPORT_EVERY == 0:
            rate = REPORT_EVERY / max(now - last, 0.001)
            last = now
            addrs = sorted({hex(s.addr) for s in simgr.active[:8]})
            print(
                f"[t={elapsed():.1f}s step={step} rate={rate:.2f} steps/s] "
                f"{state_summary()} addrs={addrs}"
            )

        if simgr.errored:
            print("[!] Error appeared, stopping early.")
            break

        if found_states:
            break

        if not simgr.active:
            print("[-] No active states left.")
            break

except KeyboardInterrupt:
    print("\n[!] Interrupted by user.")

print(f"[+] Finished after {elapsed():.1f}s")
print(f"[+] Final: {state_summary()}")

if simgr.errored:
    print("[!] Errored states:")
    for i, e in enumerate(simgr.errored[:5]):
        print(f"--- error {i} ---")
        print("state addr:", hex(e.state.addr) if e.state is not None else None)
        print("error:", repr(e.error))
        print("traceback:")
        print(e.traceback)

if not found_states:
    print("[-] No solution found in this run.")
    raise SystemExit(1)

found = found_states[0]
solution = "".join(str(found.solver.eval(b)) for b in bits)

print("[+] Solution as 64-character password:")
print(solution)
print("[+] Sanity bytes:")
print([found.solver.eval(b) for b in bits])
