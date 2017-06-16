#
#	Makefile for CODEC
#

all: encode decode
decode: decode.c decode.h 
	gcc -c buildData.c cmdPayload.c conversion.c gpsPayload.c msgPayload.c statusPayload.c
	gcc -Wall -Wextra -Wpedantic -Wwrite-strings -Wstack-usage=1024 -Wfloat-equal -Waggregate-return -Winline -o decode decode.c buildData.o cmdPayload.o conversion.o gpsPayload.o msgPayload.o statusPayload.o -lm
	
encode: encode.c encode.h
	gcc -c build.c fillPayload.c
	gcc -Wall -Wextra -Wpedantic -Wwrite-strings -Wstack-usage=1024 -Wfloat-equal -Waggregate-return -Winline -o encode encode.c build.o fillPayload.o -lm

debug: 
	gcc -c buildData.c cmdPayload.c conversion.c gpsPayload.c msgPayload.c statusPayload.c
	gcc -g -Wall -Wextra -Wpedantic -Wwrite-strings -Wstack-usage=1024 -Wfloat-equal -Waggregate-return -Winline -o decode decode.c buildData.o cmdPayload.o conversion.o gpsPayload.o msgPayload.o statusPayload.o -lm
	gcc -c build.c fillPayload.c
	gcc -g -Wall -Wextra -Wpedantic -Wwrite-strings -Wstack-usage=1024 -Wfloat-equal -Waggregate-return -Winline -o encode encode.c build.o fillPayload.o -lm

clean: 
	rm *.o encode decode *.pcap
