CXX = g++
CXXFLAGS = -g -Wall -Werror -std=gnu++23 -I ../../../include
CC = gcc
CFLAGS = -g -Wall -Werror -std=gnu23 -I ../../../include
SAN = -fsanitize=undefined,address,leak

CXXFLAGS += $(SAN)
CFLAGS += $(SAN)

all : test_dyntrie

test_dyntrie : test_dyntrie.cpp dyntrie.o

dyntrie.o : ../../dyntrie.c
	$(CC) -c $(CFLAGS) $^ -o$@

clean :
	-rm -f test_dyntrie *.o

