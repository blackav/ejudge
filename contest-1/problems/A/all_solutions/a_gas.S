        .global main
        .extern scanf
        .extern printf
        .text
main:
        pushl   %ebp
        movl    %esp, %ebp
        subl    $8, %esp
        leal    -8(%ebp), %eax
        pushl   %eax
        leal    4(%eax), %eax
        pushl   %eax
        pushl   $str1
        call    scanf
        add     $12, %esp
        movl    -8(%ebp), %eax
        addl    -4(%ebp), %eax
        pushl   %eax
        pushl   $str2
        call    printf
        addl    $8, %esp
        pushl   $0
        call    exit
str1:   .asciz  "%d%d"
str2:   .asciz  "%d\n"
