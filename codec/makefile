#
#	MAKE FILE FOR decode.c
#
#
#

all: decode encode

decode: decode.c decodelib.a decode.h
	gcc -Wall -Wextra -Wpedantic -Wwrite-strings -Wstack-usage=1024 -Wfloat-equal -Waggregate-return -Winline -o decode decode.c decodelib.a -lm

encode: encode.c encodelib.a encode.h
	gcc -Wall -Wextra -Wpedantic -Wwrite-strings -Wstack-usage=1024 -Wfloat-equal -Waggregate-return -Winline -o encode encode.c encodelib.a -lm

d_debug: decode.c decode.h
	gcc -g -Wall -o d_debug decode.c decodelib.a -lm
e_debug: encode.c encode.h
	gcc -g -Wall -o e_debug encode.c decodelib.a -lm
clean:
	rm decode encode d_debug e_debug
