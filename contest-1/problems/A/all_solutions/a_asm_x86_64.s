        .att_syntax noprefix
        .text
        .global main
main:
        sub     $8, rsp
        xor     eax, eax
        lea     .L1(rip), rdi
        mov     rsp, rsi
        lea     4(rsp), rdx
        call    scanf
        xor     eax, eax
        lea     .L2(rip), rdi
        mov     (rsp), esi
        add     4(rsp), esi
        call    printf
        add     $8, rsp
        xor     rax, rax
        ret
        .section    .string, "aMS", @progbits, 1
.L1:    .asciz  "%d%d"
.L2:    .asciz  "%d\n"

