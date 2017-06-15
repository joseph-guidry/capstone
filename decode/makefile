#
#	MAKE FILE FOR decode.c
#
#
#

all: decode

decode: decode.c decode.h statusPayload.o decodelib.a
	gcc -Wall -Wextra -Wpedantic -Wwrite-strings -Wstack-usage=1024 -Wfloat-equal -Waggregate-return -Winline -o decode decode.c statusPayload.o decodelib.a -lm
		
debug: decode.c decode.h
	gcc -g -Wall -o debug decode.c decodelib.a -lm
clean:
	rm decode
