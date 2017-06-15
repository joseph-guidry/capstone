#
#	makefile for encode program
#

all: encode

encode: encode.c encodelib.a encode.h
	gcc -Wall -Wextra -Wpedantic -Wwrite-strings -Wstack-usage=1024 -Wfloat-equal -Waggregate-return -Winline -o encode encode.c encodelib.a -lm

debug: encode.c encode.h
	gcc -g -Wall -o debug encode.c -lm

clean: all
	rm encode
