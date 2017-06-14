#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <math.h>
#include <inttypes.h>
#include "decode.h"


int main (int argc, char **argv)
{
	FILE *fp;
	struct zergPacket pcapfile;
	int msgType, filesize, sum;
	char filename[25];
	if (argc > 2)
	{
		fprintf(stderr, "%s: usage error\n", argv[0]);
		exit(1);
	}
	//Fill pcap structure with individual header structures.
	strcpy(filename, argv[1]);
	fp = buildPcapData(&pcapfile, filename, &filesize);
	
	while((ftell(fp) < filesize) && ((filesize - ftell(fp)) > 60))
	{
		fp = buildPacketData(&pcapfile, fp);
		printf("Version: %u \n", htonl(pcapfile.pcapZerg.ver_type_totalLen) >> 28);
		printf("Sequence: %u \n", htonl(pcapfile.pcapZerg.seqID));
		printf("From: %u\n", htons(pcapfile.pcapZerg.sourceID));
		printf("To: %u\n", htons(pcapfile.pcapZerg.destID));
	
		msgType = ((htonl(pcapfile.pcapZerg.ver_type_totalLen) >> 24) & 0x0f);
		switch (msgType)
		{
			case 0:
				fp = printMsgPayload(&pcapfile, fp);
				break;
			case 1:
				fp = printStatusPayload(&pcapfile, fp);
				break;
			case 2:
				fp = printCmdPayload(fp);
				break;
			case 3:
				fp = printGpsPayload(fp);
				break;
			default:
				printf("Unknown payload type\n");
				break;
		}
		//HANDLE PADDING OR BLANK FCS at end of the pcap.
		fread(filename, 1, 8, fp);
		for (unsigned int x = 0; x < strlen(filename); x++)
		{
			sum += filename[x];
			if (sum != 0)
			{
				fseek(fp, -8, SEEK_CUR);
				break;
			}
		}
		
		
	}
	fclose(fp);
	return 0;
}

//FILE * printCmdPayload (struct zergPacket * pcapfile, FILE *fp)
FILE * printCmdPayload (FILE *fp)
{
	struct commandPayload pcap;
	uint16_t param1;
	uint32_t param2;
	int command;
	
	fread(&pcap, 1, 2, fp);
	command = htons(pcap.command);
	
	if ((command % 2) == 1)
	{
		fread(&pcap.parameter1, 1, 2, fp);
		fread(&pcap.parameter2, 1, 4, fp);
	}
	
	switch (command) 
	{
		case 0:
			printf("GET_STATUS\n");
			break;
		case 1:
			param1 = htons(pcap.parameter1);
			param2 = htonl(pcap.parameter2);
			printf("GO_TO %d %.1f\n", param1, convertBin32toDecimal(param2));
			break;
		case 2:
			printf("GET_GPS\n");
			break;
		case 3:
			printf("RESERVED\n");
			break;
		case 4:
			printf("RETURN\n");
			break;
		case 5:
			param1 = htons(pcap.parameter1);
			param2 = htonl(pcap.parameter2);
			printf("SET_GROUP %d %s\n", param2, (param1 == 1)? "ADD": "REMOVE");
			break;
		case 6:
			printf("STOP\n");
			break;
		case 7:
			param1 = htons(pcap.parameter1);
			param2 = htonl(pcap.parameter2);
			printf("REPEAT %u\n", param2);
			break;
		default:
			printf("Unknown\n");
			break;
	}
	return fp;
}


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
	
	printf("Altitude:  %.6fm\n", (convertBin32toDecimal(htonl(pcap.altitude)))* 1.8288);
	printf("Bearing:   %.6f deg.\n", convertBin32toDecimal(htonl(pcap.bearing)));
	printf("Speed:     %dkm/h\n", (int)((convertBin32toDecimal(htonl(pcap.speed))) * 3.6));
	printf("Accuracy:  %dm\n", (int) convertBin32toDecimal(htonl(pcap.accuracy)));
	
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
	printf("%.2f\"", sec);
}

FILE * printStatusPayload (struct zergPacket * pcapfile, FILE *fp)
{
	struct statusPayload pcap;
	int c, msgLength;
	double zergSpeed;
	char zergType[15];
	
	// Position prior to reading status payload header.
	fread(&pcap, 1, 12, fp);  
	msgLength = ((htonl(pcapfile->pcapZerg.ver_type_totalLen) & 0xfffff) - sizeof(struct zergHeader));
	if (msgLength <= 0)
	{
		fprintf(stderr, "No message available\n");
		return fp;
	}
	msgLength = msgLength - 12;  // 12 = number of bytes in payload header
	//Get STATUS PAYLOAD NAME
	pcap.zergName = (char *) malloc (msgLength * sizeof(char));
	if ( pcap.zergName == NULL)
	{
		fprintf(stderr, "Not enough memory\n");
		exit(1);
	}
	for (int x = 0; x < msgLength; x++)
	{
		c = fgetc(fp);
		if (c == EOF)
		{
			break;
		}
		pcap.zergName[x] = c;
	}
	printf("Name : %s \n", pcap.zergName);
	printf("HP: %u/%u\n",(htonl(pcap.hitPoints) >> 8), (htonl(pcap.maxHitPoints) >> 8) );
	getZergType(zergType, (htonl(pcap.maxHitPoints) & 0xff));
	printf("Type: %s \n" ,zergType);
	printf("Armor: %x \n", htonl(pcap.hitPoints) & 0xff);
	zergSpeed = convertBin32toDecimal(htonl(pcap.speed));
	printf("MaxSpeed: %.4fm/s\n", zergSpeed);
	return fp; 
}

void getZergType(char * test, int x)
{
	switch (x)
	{
		case 0:
			strcpy(test, "Overmind");
			break;
		case 1:
			strcpy(test, "Larva");
			break;
		case 2:
			strcpy(test, "Cerebrate");
			break;
		case 3:
			strcpy(test, "Overlord");
			break;
		case 4:
			strcpy(test, "Queen");
			break;
		case 5:
			strcpy(test, "Drone");
			break;
		case 6:
			strcpy(test, "Zergling");
			break;
		case 7:
			strcpy(test, "Lurker");
			break;
		case 8:
			strcpy(test, "Broodling");
			break;
		case 9:
			strcpy(test, "Hydralisk");
			break;
		case 10:
			strcpy(test, "Guardian");
			break;
		case 11:
			strcpy(test, "Scourge");
			break;
		case 12:
			strcpy(test, "Ultralisk");
			break;
		case 13:
			strcpy(test, "Mutalisk");
			break;
		case 14:
			strcpy(test, "Defiler");
			break;
		case 15:
			strcpy(test, "Devourer");
			break;
		default:
			printf("Unknown Type\n");
			break;
	}
}

FILE * printMsgPayload (struct zergPacket * pcapfile, FILE *fp)
{
	struct msgPayload pcap;
	int msgLength;
	int c;
	
	msgLength = ((htonl(pcapfile->pcapZerg.ver_type_totalLen) & 0xffffff) - 12);
	if (msgLength <= 0)
	{
		fprintf(stderr, "No message available\n");
		return fp;
	}
	pcap.message = (char *) malloc (msgLength * sizeof(char));
	if ( pcap.message == NULL)
	{
		fprintf(stderr, "Not enough memory\n");
		exit(1);
	}
	for (int x = 0; x < msgLength; x++)
	{
		c = fgetc(fp);
		if (c == EOF)
		{
			break;
		}
		pcap.message[x] = c;
	}
	printf("Message: %s", pcap.message);
	return fp;
}

FILE * buildPcapData(struct zergPacket * pcap, char *filename, int * filesize)
{
	FILE *fp;
	struct filepcap filetest;
	
	fp = fopen(filename, "rb");
	if (fp == NULL)
	{
		fprintf(stderr, "Could not open %s \n", filename);
		exit(1);
	}
	//GET FILESIZE
	fseek(fp, 0, 2);
	*filesize = ftell(fp);
	fseek(fp, 0, 0);
	fread(&filetest, 1, sizeof(struct filepcap),  fp);
	pcap->fileHeader = filetest;
	return fp;
}

FILE * buildPacketData( struct zergPacket * pcap, FILE *fp )
{
	struct headerpcap headertest;
	struct etherFrame ethertest;
	struct ipv4Header iptest;
	struct udpHeader udptest;
	struct zergHeader zergtest;
	
	fread(&headertest, 1, sizeof(struct headerpcap),  fp);
	pcap->packetHeader = headertest;
	fread(&ethertest, 1, sizeof(struct etherFrame),  fp);
	pcap->pcapFrame = ethertest;
	fread(&iptest, 1, sizeof(struct ipv4Header),  fp);
	pcap->pcapIpv4 = iptest;
	fread(&udptest, 1, sizeof(struct udpHeader),  fp);
	pcap->pcapUdp = udptest;
	fread(&zergtest, 1, sizeof(struct zergHeader),  fp);
	pcap->pcapZerg = zergtest;
	
	return fp;
}
