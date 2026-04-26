from elftools.elf.elffile import ELFFile
from capstone import *
import sys

LIB = "level4_extract/lib/arm64-v8a/libnative_level_4.so"

# Put failed address here.
ADDR = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x5b1808

with open(LIB, "rb") as f:
    elf = ELFFile(f)
    text = elf.get_section_by_name(".text")
    text_addr = text["sh_addr"]
    text_size = text["sh_size"]
    text_off = text["sh_offset"]

    print(f"[+] .text addr: {hex(text_addr)} .. {hex(text_addr + text_size)}")
    print(f"[+] requested addr: {hex(ADDR)}")

    candidates = [ADDR]

    # If user gave Ghidra-rebased addr, convert to ELF-ish.
    if ADDR >= 0x100000:
        candidates.append(ADDR - 0x100000)

    # If user gave ELF-ish addr, convert to Ghidra-ish.
    candidates.append(ADDR + 0x100000)

    chosen = None
    for c in candidates:
        if text_addr <= c < text_addr + text_size:
            chosen = c
            break

    if chosen is None:
        print("[!] Address not inside .text in either form.")
        print("[!] Tried:", [hex(c) for c in candidates])
        raise SystemExit(1)

    print(f"[+] chosen ELF address: {hex(chosen)}")
    print(f"[+] chosen Ghidra-style address: {hex(chosen + 0x100000)}")

    start = max(text_addr, chosen - 0x80)
    end = min(text_addr + text_size, chosen + 0x80)

    f.seek(text_off + (start - text_addr))
    code = f.read(end - start)

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

for insn in md.disasm(code, start):
    marker = "   <--- TARGET" if insn.address == chosen else ""
    print(f"0x{insn.address:x} / 0x{insn.address + 0x100000:x}:\t{insn.mnemonic:8}\t{insn.op_str}{marker}")
