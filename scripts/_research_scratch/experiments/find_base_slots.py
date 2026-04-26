from elftools.elf.elffile import ELFFile
from capstone import *
from capstone.arm64 import *
from collections import Counter, defaultdict

LIB = "level4_extract/lib/arm64-v8a/libnative_level_4.so"
BASE = 0x100000
START = 0x1205f8 - BASE
END = 0x65c500 - BASE

with open(LIB, "rb") as f:
    elf = ELFFile(f)
    text = elf.get_section_by_name(".text")
    text_addr = text["sh_addr"]
    text_off = text["sh_offset"]
    f.seek(text_off + (START - text_addr))
    code = f.read(END - START)

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

slot_loads = Counter()
recent = {}

for insn in md.disasm(code, START):
    # track ldr xN, [sp, #slot]
    if insn.mnemonic == "ldr" and len(insn.operands) == 2:
        dst = insn.operands[0]
        src = insn.operands[1]
        if dst.type == ARM64_OP_REG and src.type == ARM64_OP_MEM:
            dst_name = insn.reg_name(dst.reg)
            base_name = insn.reg_name(src.mem.base)
            if dst_name in ("x8", "x9", "x10", "x11") and base_name == "sp":
                recent[dst_name] = src.mem.disp
                slot_loads[(dst_name, src.mem.disp)] += 1

    # count memory access using those regs shortly after
    if insn.mnemonic in ("ldrb", "strb", "sturb") and len(insn.operands) == 2:
        mem = insn.operands[1]
        if mem.type == ARM64_OP_MEM:
            base = insn.reg_name(mem.mem.base)
            if base in recent:
                print(f"0x{insn.address+BASE:x}: {insn.mnemonic:5} {insn.op_str:25} base {base} came from [sp+{hex(recent[base])}]")

print("\n[+] stack pointer base loads:")
for (reg, slot), count in slot_loads.most_common():
    print(f"{reg} <- [sp+{hex(slot)}]: {count}")
