#
#	makefile for encode program
#

all: encode

encode: encode.c encode.h
	gcc -Wall -o encode encode.c -lm

debug: encode.c encode.h
	gcc -g -Wall -o debug encode.c -lm

clean: all
	rm encode
