from pathlib import Path
from elftools.elf.elffile import ELFFile
from capstone import *

LIB = "level4_extract/lib/arm64-v8a/libnative_level_4.so"

# Ghidra rebased addresses:
BASE = 0x100000
Z1BPB_GHIDRA = 0x1200c8
CHECK_GHIDRA = 0x65c3f8
XOR_PLT_GHIDRA = 0x6862f0

# Convert to ELF virtual addresses:
start = Z1BPB_GHIDRA - BASE
end = CHECK_GHIDRA - BASE
xor_plt = XOR_PLT_GHIDRA - BASE

with open(LIB, "rb") as f:
    elf = ELFFile(f)
    text = elf.get_section_by_name(".text")
    text_addr = text["sh_addr"]
    text_off = text["sh_offset"]

    file_start = text_off + (start - text_addr)
    file_end = text_off + (end - text_addr)

    f.seek(file_start)
    code = f.read(file_end - file_start)

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

xor_calls = 0
all_calls = 0
first = []
last = []

for insn in md.disasm(code, start):
    if insn.mnemonic == "bl":
        all_calls += 1
        target = insn.operands[0].imm
        if target == xor_plt:
            xor_calls += 1
            if len(first) < 5:
                first.append(insn.address)
            last.append(insn.address)
            if len(last) > 5:
                last.pop(0)

print(f"_Z1bPb range: {hex(start)} -> {hex(end)}")
print(f"XOR PLT target: {hex(xor_plt)}")
print(f"All BL calls in range: {all_calls}")
print(f"XOR helper calls: {xor_calls}")
print(f"First XOR call addresses: {[hex(x) for x in first]}")
print(f"Last XOR call addresses: {[hex(x) for x in last]}")

if xor_calls:
    done = 119998
    print(f"Progress at xor_hits={done}: {done / xor_calls * 100:.2f}%")
