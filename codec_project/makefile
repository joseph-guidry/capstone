#
#	MAKE FILE FOR decode.c
#
#
#

all: decode encode

decode: decode.c decode.h
	gcc -Wall -Wextra -Wpedantic -Wwrite-strings -Wstack-usage=1024 -Wfloat-equal -Waggregate-return -Winline -o decode decode.c -lm

encode: encode.c encode.h
	gcc -Wall -Wextra -Wpedantic -Wwrite-strings -Wstack-usage=1024 -Wfloat-equal -Waggregate-return -Winline -o encode encode.c -lm

d_debug: decode.c decode.h
	gcc -g -Wall -o d_debug decode.c -lm
e_debug: encode.c encode.h
	gcc -g -Wall -o e_debug encode.c -lm
clean:
	rm decode encode d_debug e_debug
