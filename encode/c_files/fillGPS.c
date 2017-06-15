#include "encode.h"

unsigned long fillGpsPayload (struct zergPacket * pcap, FILE * fp)
{
	struct gpsDataPayload test;
	char coordinates[60], string[20], input[10], trash[5];
	char direction;
	
	fgets(coordinates, 50, fp);
	sscanf(coordinates, "%s %s %s", input, trash, &direction);
	test.latitude.value = atof(input) * ( (direction == 'E'? -1 : 1) );
	test.latitude.value64 = swapLong(test.latitude.value64);
	
	fgets(coordinates, 60, fp);
	sscanf(coordinates, "%s %s %s %s", string, input, trash, &direction);
	test.longitude.value = atof(input) * ( (direction == 'S'? -1 : 1) );
	test.longitude.value64 = swapLong(test.longitude.value64);
	
	fgets(coordinates, 60, fp);
	sscanf(coordinates, "%s %s", string, input);
	test.altitude.value = (atof(input) /1.8288);
	test.altitude.value32 = ntohl(test.altitude.value32);
	
	fgets(coordinates, 60, fp);
	sscanf(coordinates, "%s %s", string, input);
	test.bearing.value = atof(input);
	test.bearing.value32 = ntohl(test.bearing.value32);
	
	fgets(coordinates, 60, fp);
	sscanf(coordinates, "%s %s", string, input);
	test.speed.value = (atof(input) / 3.6);
	test.speed.value32 = ntohl(test.speed.value32);
	
	fgets(coordinates, 60, fp);
	sscanf(coordinates, "%s %s", string, input);
	test.accuracy.value = atof(input);
	test.accuracy.value32 = ntohl(test.accuracy.value32);
	
	pcap->output.gps = test;
	
	return 32;  //Number of bytes in GPS Payload.
}

uint64_t swapLong( uint64_t x)
{
	x = ((x << 8 ) & 0xFF00FF00FF00FF00ULL)  | ((x >> 8)  &  0x00FF00FF00FF00FFULL);
	x = ((x << 16 ) &  0xFFFF0000FFFF0000ULL) | ((x >> 16) &  0x0000FFFF0000FFFFULL);
	
	return (x << 32) | (x >> 32);
}
