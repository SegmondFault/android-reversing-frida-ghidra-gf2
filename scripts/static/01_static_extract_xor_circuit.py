from pathlib import Path
from elftools.elf.elffile import ELFFile
from capstone import *
from capstone.arm64 import *
import json

LIB = "level4_extract/lib/arm64-v8a/libnative_level_4.so"

BASE = 0x100000

# Start of the generated XOR circuit.
CIRCUIT_START_GHIDRA = 0x1205f8

# End around the epilogue area.
CIRCUIT_END_GHIDRA = 0x65c500

# XOR helper PLT.
XOR_PLT_GHIDRA = 0x6862f0

# Stack slots holding buffer base pointers.
# Instead of manually mapping a few slots to M/S, we namespace each stack slot:
#   [sp+0x50]  -> B50
#   [sp+0x110] -> B110
#   [sp+0x128] -> B128
STACK_BASE_SLOTS = {}

def ghidra_to_elf(addr):
    return addr - BASE

def reg_name(insn, reg_id):
    return insn.reg_name(reg_id)

def read_text_range(path, start_elf, end_elf):
    with open(path, "rb") as f:
        elf = ELFFile(f)
        text = elf.get_section_by_name(".text")
        text_addr = text["sh_addr"]
        text_off = text["sh_offset"]

        file_start = text_off + (start_elf - text_addr)
        file_end = text_off + (end_elf - text_addr)

        f.seek(file_start)
        return f.read(file_end - file_start)

def is_bl_to_xor(insn, xor_plt_elf):
    if insn.mnemonic != "bl":
        return False
    if len(insn.operands) != 1:
        return False
    op = insn.operands[0]
    return op.type == ARM64_OP_IMM and op.imm == xor_plt_elf

def get_mem_base_disp(insn, op_index):
    op = insn.operands[op_index]
    if op.type != ARM64_OP_MEM:
        return None
    return insn.reg_name(op.mem.base), op.mem.disp

def get_dst_reg(insn):
    if not insn.operands:
        return None
    op = insn.operands[0]
    if op.type != ARM64_OP_REG:
        return None
    return insn.reg_name(op.reg)

def get_src_reg(insn, index):
    if len(insn.operands) <= index:
        return None
    op = insn.operands[index]
    if op.type != ARM64_OP_REG:
        return None
    return insn.reg_name(op.reg)

def canon_w(reg):
    """
    Normalise x8/w8 style names to w-register names for value tracking.
    """
    if reg is None:
        return None
    if reg.startswith("x") and reg[1:].isdigit():
        return "w" + reg[1:]
    return reg

def canon_x(reg):
    """
    Normalise w8/x8 style names to x-register names for pointer tracking.
    """
    if reg is None:
        return None
    if reg.startswith("w") and reg[1:].isdigit():
        return "x" + reg[1:]
    return reg

start_elf = ghidra_to_elf(CIRCUIT_START_GHIDRA)
end_elf = ghidra_to_elf(CIRCUIT_END_GHIDRA)
xor_plt_elf = ghidra_to_elf(XOR_PLT_GHIDRA)

code = read_text_range(LIB, start_elf, end_elf)

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True
insns = list(md.disasm(code, start_elf))

# Pointer register state:
#   ptr_base["x8"] = "M" means x8 points to main work buffer.
#   ptr_base["x9"] = "S" means x9 points to secondary buffer.
#
# At the circuit entry, x8 is already the main work-buffer base.
ptr_base = {"x8": "B50"}

# Value register state:
#   val_src["w9"] = ("M", 0xec5) means w9 contains M[0xec5].
#   val_src["w0"] = ("ARG", ("M", 0xec5)) means w0 contains arg derived from M[0xec5].
#   val_src["w10"] = ("RET", call_addr) means w10 contains the XOR result.
val_src = {}

gates = []
xor_calls = 0
pending = None
missed = []

for idx, insn in enumerate(insns):
    gaddr = insn.address + BASE

    # Track pointer loads:
    #   ldr x8, [sp, #0x118] -> x8 points to M
    #   ldr x9, [sp, #0x110] -> x9 points to S
    if insn.mnemonic == "ldr" and len(insn.operands) == 2:
        dst = get_dst_reg(insn)
        mem = get_mem_base_disp(insn, 1)

        if dst and mem:
            base_reg, disp = mem
            if base_reg == "sp":
                ptr_base[canon_x(dst)] = f"B{disp:x}"

    # Track byte loads from known buffers:
    #   ldrb w9, [x8, #0xec5] where x8 -> M
    #   val_src[w9] = ("M", 0xec5)
    if insn.mnemonic == "ldrb" and len(insn.operands) == 2:
        dst = canon_w(get_dst_reg(insn))
        mem = get_mem_base_disp(insn, 1)

        if dst and mem:
            base_reg, disp = mem
            base_kind = ptr_base.get(canon_x(base_reg))
            if base_kind:
                val_src[dst] = (base_kind, disp)
            elif base_reg == "sp":
                val_src[dst] = ("STK", disp)
            else:
                val_src[dst] = ("UNK", disp, base_reg)

    # Track:
    #   and w0, w9, #1
    #   and w1, w8, #1
    #   and w9, w0, wmask
    #
    # If source reg had a symbolic source, preserve it.
    # Important: after bl _Z1abb, w0 contains ("RET", call_addr).
    # The common store pattern is:
    #   and w9, w0, wmask
    #   strb w9, [buf, #out]
    if insn.mnemonic == "and" and len(insn.operands) >= 2:
        dst = canon_w(get_dst_reg(insn))
        src1 = canon_w(get_src_reg(insn, 1))

        if dst and src1 and src1 in val_src:
            val_src[dst] = val_src[src1]

    # XOR helper call.
    if is_bl_to_xor(insn, xor_plt_elf):
        if pending:
            missed.append({
                "call_addr": pending["call_addr"],
                "reason": "new XOR call before previous return was stored",
                "in_a": repr(pending["in_a"]),
                "in_b": repr(pending["in_b"]),
            })
            pending = None

        xor_calls += 1

        in_a = val_src.get("w0")
        in_b = val_src.get("w1")

        if in_a is None or in_b is None:
            missed.append({
                "call_addr": gaddr,
                "reason": "missing w0/w1 sources",
                "w0": repr(in_a),
                "w1": repr(in_b),
            })
            pending = None
        else:
            pending = {
                "call_addr": gaddr,
                "in_a": in_a,
                "in_b": in_b,
            }

        # Return value comes back in w0.
        val_src["w0"] = ("RET", gaddr)
        continue

    # Propagate XOR return through:
    #   and w9, w0, wmask
    # This was already mostly handled by the generic AND rule, but make explicit.
    if insn.mnemonic == "and" and len(insn.operands) >= 2:
        dst = canon_w(get_dst_reg(insn))
        src1 = canon_w(get_src_reg(insn, 1))
        if dst and src1 and val_src.get(src1, (None,))[0] == "RET":
            val_src[dst] = val_src[src1]

    # Store result:
    #   strb w9, [x8, #out]
    #   strb w10, [sp, #out]
    #
    # If there is a pending XOR call and the stored source register currently
    # contains that XOR return value, record the gate.
    # Special final-output pattern:
    #   bl      xor_func        ; w0 = symbolic xor result
    #   ldr     w8, [sp,#0x138] ; runtime mask, observed == 1
    #   and     w8, w0, w8
    #
    # Since the mask low bit is 1, the stored byte tracks w0.
    if insn.mnemonic == "and":
        dst = canon_w(get_dst_reg(insn))
        src1 = canon_w(get_src_reg(insn, 1))
        src2 = canon_w(get_src_reg(insn, 2)) if len(insn.operands) > 2 else None
        if dst == "w8" and src1 == "w0" and src2 == "w8" and "w0" in val_src:
            val_src["w8"] = val_src["w0"]

    if insn.mnemonic in ("strb", "sturb") and len(insn.operands) == 2:
        src = canon_w(get_src_reg(insn, 0))
        mem = get_mem_base_disp(insn, 1)

        if pending and src and mem:
            src_val = val_src.get(src)

            base_reg, disp = mem
            out_base = ptr_base.get(canon_x(base_reg))

            if out_base is None and base_reg == "sp":
                out_base = "STK"

            if src_val and src_val[0] == "RET":
                gates.append({
                    "call_addr": pending["call_addr"],
                    "in_a": pending["in_a"],
                    "in_b": pending["in_b"],
                    "out": (out_base if out_base else "UNK", disp, base_reg if out_base is None else None),
                    "store_addr": gaddr,
                })
                pending = None

# If something is still pending at the end, count it as missed.
if pending:
    missed.append({
        "call_addr": pending["call_addr"],
        "reason": "pending return never stored",
        "in_a": repr(pending["in_a"]),
        "in_b": repr(pending["in_b"]),
    })

print(f"[+] XOR calls seen: {xor_calls}")
print(f"[+] Gates extracted: {len(gates)}")
print(f"[+] Missed gates: {xor_calls - len(gates)}")

if gates:
    print("[+] First 5 gates:")
    for g in gates[:5]:
        print(f"    {g['out']} = {g['in_a']} XOR {g['in_b']}")

    print("[+] Last 5 gates:")
    for g in gates[-5:]:
        print(f"    {g['out']} = {g['in_a']} XOR {g['in_b']}")

Path("xor_circuit.json").write_text(json.dumps(gates, indent=2))
Path("xor_circuit_missed.json").write_text(json.dumps(missed[:500], indent=2))

print("[+] Wrote xor_circuit.json")
print("[+] Wrote xor_circuit_missed.json with first 500 misses")

if missed:
    print("[!] First 10 misses:")
    for m in missed[:10]:
        print("   ", m)
