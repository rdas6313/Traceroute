CC=gcc
CFLAGS=-c
DEBUG_FLAGS=-DDEBUG=1

Traceroute: Traceroute.o Traceroute_tool.o 
	$(CC) $^ -o $@

%.o: %.c
	$(CC) $(CFLAGS) $^ -o $@

DEBUG: 
	$(CC) $(DEBUG_FLAGS) $(CFLAGS) Traceroute.c Traceroute_tool.c
	make

clear:
	rm -f *.o 