.PHONY: clean all
CC=gcc
FLAGS= -Wall -g
AR=ar

Sniffer.o: Sniffer.c
	$(CC) -c Sniffer.c -lpcap

Gateway.o: Gateway.c
	$(CC) -c $(FLAGS) Gateway.c

sniffer: Sniffer.o
	gcc -Wall Sniffer.o -o sniffer -lpcap

gateway: Gateway.o
	gcc -Wall Gateway.o -o gateway 

all: sniffer gateway 

clean:
	rm -rf *.o sniffer gateway