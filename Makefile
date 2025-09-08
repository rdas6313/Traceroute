CC=gcc
CFLAGS=-c

Traceroute: Traceroute.o Traceroute_tool.o 
	$(CC) $^ -o $@

%.o: %.c
	$(CC) $(CFLAGS) $^ -o $@

clear:
	rm -f *.o 