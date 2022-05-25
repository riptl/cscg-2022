start:
    # Read disk
    mov ax, 0x202
    mov bx, 0x9000
    mov dx, 0x82
    mov cx, 0x1
    int 0x13

    mov si, 0x9000
print:
    lodsb
    or al, al
    jz done
    mov ah, 0x0e
    int 0x10
    jmp print

done:
    cli
    hlt
