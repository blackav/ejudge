    .text
    .global main
main:
    pushl   $y
    pushl   $x
    pushl   $s1
    call    scanf
    add     $12, %esp
    movl    x, %eax
    addl    y, %eax
    pushl   %eax
    pushl   $s2
    call    printf
    add     $8, %esp
    xorl    %eax, %eax
    ret

    .data
x:  .int    0
y:  .int    0
s1: .asciz  "%d%d"
s2: .asciz  "%d\n"
    .align  4
