from elftools.elf.elffile import ELFFile
from capstone import *

LIB = "level4_extract/lib/arm64-v8a/libnative_level_4.so"

# ELF addresses. Ghidra-style = +0x100000.
START = 0x55c240
END   = 0x55c520

with open(LIB, "rb") as f:
    elf = ELFFile(f)
    text = elf.get_section_by_name(".text")
    text_addr = text["sh_addr"]
    text_off = text["sh_offset"]

    f.seek(text_off + (START - text_addr))
    code = f.read(END - START)

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

for insn in md.disasm(code, START):
    print(f"0x{insn.address:x} / 0x{insn.address + 0x100000:x}:\t{insn.mnemonic:8}\t{insn.op_str}")
