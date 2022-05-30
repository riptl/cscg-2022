Input: ROM and state file

## Binary

- ASLR
- No Execute

## Memory access vulnerability

The Gameboy uses 16-bit addressing. It also uses memory segmentation to switch between "banks" of memory to increase the total amount of available memory.
The Gearboy emulator persists the selected memory banks in the state file.
However, when loading the state file, it does not perform any bounds checks on these indices.
This allows us to break past the bounds of the emulator memory buffers, and instead map arbitrary heap space into the emulator.
From inside the emulator, memory is accessible simply through load/store instructions.

In particular, two input parameters are of interest.

### WRAM bank

- State parameter `Memory::m_iCurrentWRAMBank` is not bounds checked
- `Memory::m_iCurrentWRAMBank` used as array index (* 0x1000) into heap buffer `Memory::m_pWRAMBanks` of size 0x8000
- `Memory::m_pWRAMBanks` is mapped into 0xD000..0xDE00 of emulator read/write
- Therefore 0xD000..0xDE00 can point to any heap offset

### MBC1 RAM bank

- State parameter `MBC1MemoryRule::m_CurrentRAMAddress` is not bounds checked
- `MBC1MemoryRule::m_CurrentRAMAddress` used as array index into heap buffer of size 0x8000
- `MBC1MemoryRule::m_pRAMBanks + MBC1MemoryRule::m_CurrentRAMAddress` Mapped into 0x8000..0xA000 of emulator read/write
- Therefore 0x8000..0xA000 can point to any heap offset

## Stage 0: Emulator setup

### Cartridge

We start by crafting the game cartridge to create an exploitable virtual machine.
- Gameboy Color (CGB mode) to enable WRAM banks.
- Game cartridge type MBC1+RAM to enable MBC1 RAM banks.

The ROM is used to ship the logic to perform the exploit, written in Gameboy assembler.

[wla-dx](https://github.com/vhelin/wla-dx) serves as the Gameboy assembler and linker.

```
brew install wla-dx
cd ./rom
make
```

### Memory Map

The ROM file sets up a MBC1-type memory map in the emulator.

```
0x0000..0x4000: RAM
0x4000..0x8000: ROM
0x8000..0xA000: RAM bank
0xA000..0xC000: RAM bank
0xD000..0xDE00: WRAM bank 1
```

### State file

The state file serves as our entrypoint.

We start a modified version of gearboy to export a valid state file as a reference version (`./state/pwn.orig.state`).

The script `./state/craft.py` then takes the reference to generate a crafted state file.
The state file format on Linux is as follows:

```
0x00000..0x10000: Copy of ROM file content
0x10000..0x10004: `Memory::m_iCurrentWRAMBank`
0x1a020..0x1a022: `Processor::PC`
0x3de8d..0x3de91: `MBC1MemoryRule::iCurrentRAMBank`
...
```

The PC (program counter) register is reset to `0x0200` (`main`).
The `m_iCurrentWRAMBank` parameter is set as described below.

For simplicity, also added were the following commands.

```
cd ./state

make run_local # Build exploit and launch gearboy directly (macOS)
make run       # Build exploit and launch gearboy in Docker container
make run_debug # Like "run", but with Radare2 debugger
```

### Helper routines

The Gameboy CPU has 8-bit wide general-purpose registers,
so we need to implement handling of 64-bit values used in the exploit ourselves.

[`pwn.s`](./rom/pwn.s) contains a few helper macros and subroutines.
- memcpy, memset: As you know them
- memcpy_8: Copy 64-bit integer
- add_ptr_3: Add 24-bit integer to 64-bit integer
- sub_ptr_3: Subtract 24-bit integer from 64-bit integer

## Stage 1: Full memory access

### Memory Exposure

Per se, the out-of-bounds accesses using the corrupted state file entries are not exploitable,
because each segment only exposes a few thousand bytes on the heap.

To increase addressable space, we need to gain the ability to switch segments to arbitrary areas of host memory.
Specifically, we want to control the pointer `MBC1MemoryRule::m_pRAMBanks`, which controls MBC1 RAM, by exposing it in WRAM.

Using a debugger, we reveal that `MBC1MemoryRule::m_pRAMBanks` is `0x7a638` bytes before `Memory::m_pWRAMBanks`.
Thus, we set `Memory::m_iCurrentWRAMBank` in our state file to `-0x7b` (`-0x7a638 / 0x1000`).

The following emulated addresses now expose MBC1:
- `MBC1MemoryRule::m_pRAMBanks` at `0xD9C8`
- `MBC1MemoryRule::m_CurrentRAMAddress` at `0xD9D4` (12 bytes afterwards)

Radare2 was used to debug the exploit.
Useful command:
- Set breakpoint at every Gameboy instruction: ```db $$ @@= `pid 1 @@ sym.Processor::OPCode0x*` ```

### Control flow hijack

Next on the checklist:
- Defeat ASLR by revealing the gearboy `.text` base address
- Control flow hijack (set `rip`)

We can do both at once using the buffer at `Processor::m_OPCodes` (heap).
It contains a table of 256 function pointers, one for each processor opcode (`Processor::OPCode0x00` etc).

We note that `Processor::m_OPCodes` is `0x61e10` bytes before the buffer at `MBC1MemoryRule::m_pRAMBanks`.
Thus we subtract the pointer `MBC1MemoryRule::m_pRAMBanks` by `0x61e10`.

With a code offset into `gearboy:<.text>`, we can leak symbols from the shared library locations using GOT lookups.

## Stage 2: ASLR

Our best bet for exploitation is ROP.
The `gearboy` binary doesn't contain any useful vectors, so we'll use ret2libc.

This requires us to know the libc base address and stack pointer.

Currently, we only have access to the heap and gearboy base address (via the above function pointer table).

### libc base address

Using the memory r/w primitive from stage 1, we can dereference pointers.
To follow a pointer, we copy the pointer to the `m_pRAMBanks` field to map its content in `0xa000` in the emulator.

This is all we need to locate libc.
- Locate a call to a libc function in the gearboy binary,
  e.g. [this call to `fopen`](https://github.com/drhelius/Gearboy/blob/04b6751a85759af0ed126c1b0ca6685b84ebd5a9/platforms/desktop-shared/config.cpp#L264).
- Follow offset to reveal the PLT entry of `fopen`.
  ```
  0:  f3 0f 1e fa             endbr64
  4:  f2 ff 25 0d 01 04 00    bnd jmp QWORD PTR [rip+0x4010d]
  b:  0f 1f 44 00 00          nop    DWORD PTR [rax+rax*1+0x0]
  ```
- Follow offset of `jmp` instruction in PLT to reveal GOT entry.
- Read `fopen` address from GOT entry.

## Stage 3: Shell

With libc base known and RIP control, we do a classic jump to libc.

```
$ readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep ' fopen@'
   182: 0000000000082910   246 FUNC    GLOBAL DEFAULT   15 fopen@@GLIBC_2.2.5
$ one_gadget /lib/x86_64-linux-gnu/libc.so.6
0xe3afe execve("/bin/sh", r15, r12)
constraints:
  [r15] == NULL || r15 == NULL
  [r12] == NULL || r12 == NULL
$ python3
>>> hex(0xe3afe-0x0000000000082910)
'0x611ee'
```

The constraints are already met:
- `r15` already points to null bytes.
- `r12` happens to be the opcode being executed.
  We wanted to overwrite opcode `0x00` (nop) anyways, so that's fine.

We map back our `Processor::m_OPCodes` buffer from the very beginning and write our gadget address.

No operation is left to be done.

```
nop
```
