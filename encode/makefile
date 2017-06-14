#
#	makefile for encode program
#

all: encode

encode: encode.c encode.h
	gcc -Wall -Wextra -Wpedantic -Wwrite-strings -Wstack-usage=1024 -Wfloat-equal -Waggregate-return -Winline -o encode encode.c -lm

debug: encode.c encode.h
	gcc -g -Wall -o debug encode.c -lm

clean: all
	rm encode
