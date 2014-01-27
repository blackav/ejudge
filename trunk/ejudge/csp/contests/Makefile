CC = gcc
CFLAGS = -Wall -I../.. -I../../reuse/include -Wno-pointer-sign -std=gnu99

all : priv_main_page.o

priv_main_page.o : priv_main_page.c

priv_main_page.c : priv_main_page.csp
	../../ej-page-gen priv_main_page.csp > priv_main_page.c
