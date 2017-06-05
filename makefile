#
#	MAKE FILE FOR decode.c
#
#
#

all: decode

decode: decode.c decode.h
	gcc -Wall -o decode decode.c
		
clean:
	rm *
