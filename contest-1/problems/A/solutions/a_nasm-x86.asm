; $Id$
	section	.data
format1	db	"%d%d", 0
format2	db	"%d", 10, 0

	align	4
a	dq	0
b	dq	0

	section .text
	global	main
	extern	exit, scanf, printf
main:
	push	b
	push	a
	push	format1
	call	scanf
	add	esp, 12
	mov	eax, [a]
	add	eax, [b]
	push	eax
	push	format2
	call	printf
	add	esp, 8
	push	0
	call	exit
