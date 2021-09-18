# Makefile for fend
#
# Parimal Mehta

all: fend

fend:
	gcc -g fend.c -o fend

clean:
	rm fend
