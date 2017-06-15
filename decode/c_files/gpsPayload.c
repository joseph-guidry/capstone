#include "decode.h"

FILE * printGpsPayload (FILE *fp)
{
	struct gpsDataPayload pcap;
	double f_coordinate;
	int direction;
	uint64_t longitude, latitude; 
	fread(&pcap, 1, 32, fp);
	
	latitude = swapLong(pcap.latitude);
	direction = ( latitude & 0x8000000000000000);
	latitude = latitude & 0x7FFFFFFFFFFFFFFF;
	f_coordinate = convertBin64toDecimal(latitude);
	printf("Latitude:  %.6f deg. %c ", convertBin64toDecimal(latitude), direction ? 'N':'S');
	degreesConvertDMS(f_coordinate);
	printf(" %c )\n", direction ? 'N':'S');
	
	direction = ( longitude & 0x8000000000000000);
	longitude = swapLong(pcap.longitude);
	longitude = longitude & 0x7FFFFFFFFFFFFFFF;
	f_coordinate = convertBin64toDecimal(longitude);
	printf("Longitude: %.6f deg. %c ", convertBin64toDecimal(longitude), direction ? 'W':'E');
	degreesConvertDMS(f_coordinate);
	printf(" %c )\n", direction ? 'W':'E');
	
	printf("Altitude:  %.6fm\n", (convertBin32toDecimal(htonl(pcap.altitude) & 0x7FFFFFFF) )* 1.8288);
	printf("Bearing:   %.6f deg.\n", convertBin32toDecimal(htonl(pcap.bearing)& 0x7FFFFFFF) );
	printf("Speed:     %ukm/h\n", (int)((convertBin32toDecimal(htonl(pcap.speed)& 0x7FFFFFFF) ) * 3.6));
	printf("Accuracy:  %um\n", (int) convertBin32toDecimal(htonl(pcap.accuracy)));
	
	return fp;
}

void degreesConvertDMS( double degrees)
{
	uint8_t deg, min;
	double sec;
	//Convert Degress
	deg = degrees;
	printf("( %d deg. ", deg);
	//Convert mins	
	min = ((degrees - deg) * 60);
	printf("%d' ", min);
	//Convert Seconds
	sec = ((degrees - deg - ((double)min/60)) * 3600);
	printf("%.1f\"", sec);
}
