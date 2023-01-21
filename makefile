.PHONY: clean all
CC=gcc
FLAGS= -Wall -g
AR=ar

sniffer: Sniffer.c
	gcc -o sniffer Sniffer.c -lpcap

spoofer: Spoofer.c
	gcc -o spoofer Spoofer.c

snoofer: Snoofer.c
	gcc -o snoofer Snoofer.c -lpcap

gateway: Gateway.c
	gcc -o gateway Gateway.c


all: sniffer spoofer snoofer gateway 

clean:
	rm -rf sniffer spoofer snoofer gateway