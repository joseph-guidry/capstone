#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <math.h>
#include "decode.h"


FILE * buildPcapData (struct zergPacket * pcap, char * filename);
FILE * printMsgPayload (struct zergPacket * pcap, FILE *fp);
FILE * printStatusPayload (struct zergPacket * pcaps, FILE *fp);
void getZergType(char * test, int x);
double convertBintoDecimal(unsigned int speed);


int main (int argc, char **argv)
{
	FILE *fp;
	struct zergPacket pcapfile;
	int msgType;
	char filename[25];
	strcpy(filename, argv[1]);
	
	//Fill pcap structure with individual header structures.
	fp = buildPcapData(&pcapfile, filename);
	
	printf("The current position of the file: %lu\n", ftell(fp));
	
	printf("fileTypeID: %x \n", htonl(pcapfile.fileHeader.fileTypeID));
	printf("majorVersion: %x \n", htons(pcapfile.fileHeader.majorVersion));
	printf("minorVersion: %x \n", htons(pcapfile.fileHeader.minorVersion));
	printf("linkLayerType: %x \n", htons(pcapfile.fileHeader.linkLayerType));
	
	printf("dataCapture: %d \n", pcapfile.packetHeader.dataCapture);
	
	printf("Ether Type:%04x \n", htons(pcapfile.pcapFrame.etherType));
	
	printf("IP Version: [%x]\n", htons(pcapfile.pcapIpv4.ver_header) >> 12);
	printf("totalIPhdrlen: [%04x]\n", htons(pcapfile.pcapIpv4.totalIPhdrlen));
	
	printf("Source Port: %u \n", htons(pcapfile.pcapUdp.sport));
	printf("Dest Port: %u \n", htons(pcapfile.pcapUdp.dport));
	printf("Length: %u \n", htons(pcapfile.pcapUdp.udpLen));
	
	printf("Zerg Version: %x \n", htonl(pcapfile.pcapZerg.ver_type_totalLen) >> 28);
	printf("Zerg Type: %x \n", (htonl(pcapfile.pcapZerg.ver_type_totalLen) >> 24) & 0x0f);
	printf("Zerg total Length: %x \n", htonl(pcapfile.pcapZerg.ver_type_totalLen) & 0xffffff);
	printf("Zerg dest ID: %d \n", htons(pcapfile.pcapZerg.destID));
	printf("Zerg src ID: %d \n", htons(pcapfile.pcapZerg.sourceID));
	printf("Zerg SEQ ID: %d \n", htonl(pcapfile.pcapZerg.seqID));
	
	
	printf("The current position of the file: %lu\n", ftell(fp));
	
	msgType = ((htonl(pcapfile.pcapZerg.ver_type_totalLen) >> 24) & 0x0f);
	printf("msgType: %d\n", msgType);
	switch (msgType)
	{
		case 0:
			printf("This is a msg payload\n");
			fp = printMsgPayload(&pcapfile, fp);
			break;
		case 1:
			printf("This is a status payload\n");
			fp = printStatusPayload(&pcapfile, fp);
			break;
		case 2:
			printf("This is a command payload\n");
			break;
		case 3:
			printf("This is a gps status payload\n");
			break;
		default:
			printf("Unknown payload type\n");
			break;
	}	
	
	
	printf("The current position of the file: %lu\n", ftell(fp));
	fclose(fp);
	

	return 0;
}

FILE * printStatusPayload (struct zergPacket * pcapfile, FILE *fp)
{
	printf("Inside Status Payload\n");
	struct statusPayload pcap;
	int n, c, msgLength;
	//uint32_t speed;
	double zergSpeed;

	char zergType[15];
	
	printf("The current position of the file: %lu\n", ftell(fp));
	n = fread(&pcap, 1, 12, fp);
	printf("Size of header: %u \n", n);
	printf("The current position of the file: %lu\n", ftell(fp));
	
	msgLength = ((htonl(pcapfile->pcapZerg.ver_type_totalLen) & 0xfffff) - sizeof(struct zergHeader));
	printf("msgLength: %d\n", msgLength);
	
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
	
	getZergType(zergType, (htonl(pcap.maxHitPoints) & 0xff));
	
	//THe type of zerg -> needs to convert to type name ex. 6 = zergling
	printf("Zerg Type in Status Payload: %x \n", htonl(pcap.maxHitPoints) & 0xff);
	printf("Zerg name : %s \n", pcap.zergName);
	printf("Zerg Type : %s \n" ,zergType);
	
	
	//Convert SPEED from binary to Decimal 
	zergSpeed = convertBintoDecimal(htonl(pcap.speed));
	//printf("%x m/s\n", speed);
	
	/*
	mantissa = speed & 0x7fffff;
	exponent = ((speed >> 23) & 0xff) - 127;
	signedBit = speed >> 31;
	
	printf("Mantissa %d\nExponent: %d\nSigned BIt: %d \n", mantissa, exponent, signedBit);
	zergSpeed = (signedBit? -1: 1) * pow(2, exponent) * (1 +(mantissa * pow(2, -23))) ;
	*/
	printf("Zerg Speed: %.4f m/s\n", zergSpeed);
	return fp; 
}

double convertBintoDecimal(unsigned int speed)
{
	int mantissa, exponent, signedBit;
	
	mantissa = speed & 0x7fffff;
	exponent = ((speed >> 23) & 0xff) - 127;
	signedBit = speed >> 31;
	
	printf("Mantissa %d\nExponent: %d\nSigned BIt: %d \n", mantissa, exponent, signedBit);
	return (signedBit? -1: 1) * pow(2, exponent) * (1 +(mantissa * pow(2, -23))) ;
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
	
	msgLength = ((htonl(pcapfile->pcapZerg.ver_type_totalLen) & 0xfffff) - sizeof(struct zergHeader));
	printf("msgLength: %d\n", msgLength);
	
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
	printf("MSG: %s \n", pcap.message);
	putchar('\n');
	
	return fp;
}


FILE * buildPcapData(struct zergPacket * pcap, char *filename)
{
	FILE *fp;
	unsigned long n;
	
	struct filepcap filetest;
	struct headerpcap headertest;
	struct etherFrame ethertest;
	struct ipv4Header iptest;
	struct udpHeader udptest;
	struct zergHeader zergtest;	
	
	fp = fopen(filename, "rb");
	if (fp == NULL)
	{
		fprintf(stderr, "Could not open %s \n", filename);
	}
	
	printf("Opened the FILE!\n");
	
	n = fread(&filetest, 1, sizeof(struct filepcap),  fp);
	printf("Size of file: %lu \n", n);
	pcap->fileHeader = filetest;
	
	n = fread(&headertest, 1, sizeof(struct headerpcap),  fp);
	printf("Size of file: %lu \n", n);

	pcap->packetHeader = headertest;

	n = fread(&ethertest, 1, sizeof(struct etherFrame),  fp);
	printf("Size of file: %lu \n", n);
	pcap->pcapFrame = ethertest;

	n = fread(&iptest, 1, sizeof(struct ipv4Header),  fp);
	printf("Size of file: %lu \n", n);

	pcap->pcapIpv4 = iptest;

	n = fread(&udptest, 1, sizeof(struct udpHeader),  fp);
	printf("Size of file: %lu \n", n);
	
	pcap->pcapUdp = udptest;
	
	n = fread(&zergtest, 1, sizeof(struct zergHeader),  fp);
	printf("Size of file: %lu \n", n);

	pcap->pcapZerg = zergtest;

	return fp;
	
}
