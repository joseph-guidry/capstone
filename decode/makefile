#
#	MAKE FILE FOR decode.c
#
#
#

all: decode

decode: decode.c decode.h
	gcc -Wall -Wextra -Wpedantic -Wwrite-strings -Wstack-usage=1024 -Wfloat-equal -Waggregate-return -Winline -o decode decode.c -lm
		
debug: decode.c decode.h
	gcc -g -Wall -o debug decode.c -lm
clean:
	rm decode
