#include "decode.h"

uint64_t swapLong( uint64_t x)
{
	x = ((x << 8 ) & 0xFF00FF00FF00FF00ULL)  | ((x >> 8)  &  0x00FF00FF00FF00FFULL);
	x = ((x << 16 ) &  0xFFFF0000FFFF0000ULL) | ((x >> 16) &  0x0000FFFF0000FFFFULL);
	
	return (x << 32) | (x >> 32);
}

double convertBin64toDecimal(unsigned long coordinates)
{
	long mantissa;
	int exponent, signedBit;
	mantissa = coordinates & 0xfffffffffffff;
	exponent = ((coordinates >> 52) & 0x7ff) - 1023;
	signedBit = coordinates >> 63;
	
	return (signedBit? -1: 1) * pow(2, exponent) * (1 +(mantissa * pow(2, -52))) ;
} 

double convertBin32toDecimal(unsigned int speed)
{
	int mantissa, exponent, signedBit;
	mantissa = speed & 0x7fffff;
	exponent = ((speed >> 23) & 0xff) - 127;
	signedBit = speed >> 31;
	
	return (signedBit? -1: 1) * pow(2, exponent) * (1 +(mantissa * pow(2, -23))) ;
}
