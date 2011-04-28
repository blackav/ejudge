% -*- prolog -*-
:- initialization(main).
main :- read_number(A), read_number(B), C is A + B, write(C), nl, halt.

