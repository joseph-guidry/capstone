#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <math.h>
#include <inttypes.h>
#include "codec.h"

void fillMsgPayload (struct zergPacket * pcap, FILE * fp, int filesize);
void fillStatusPayload (struct zergPacket * pcap, FILE * fp, int filesize);
int getTypeNum(char * name);

void buildPcapData (struct zergPacket * pcap);
void buildPcapPacket (struct zergPacket * pcap);
void buildEtherFrame (struct zergPacket * pcap);
void buildIpHeader (struct zergPacket * pcap);
void buildUdpHeader (struct zergPacket * pcap);
void buildZergHeader (struct zergPacket *pcap);
FILE * updateZergHeader (struct zergPacket * pcap, FILE * fp);

int main(int argc, char **argv)
{
	FILE * fp;
	char string[20];
	unsigned long n, filesize;
	struct zergPacket pcapout;
	
	
	
	//while(
	fp = fopen(argv[1], "r");
	if (fp == NULL)
	{
		fprintf(stderr, "Could not open %s\n", argv[1]);
		exit(1);
	}
	fseek(fp, 0, 2);
	filesize = ftell(fp);
	printf("Filesize: %lu\n", filesize);
	fseek(fp, 0, 0);
	
	//Complete After zergHeader/Payload modifications
	printf("Filling PCAP!\n");
	buildZergHeader(&pcapout);
	buildUdpHeader(&pcapout);
	buildIpHeader(&pcapout);
	buildEtherFrame(&pcapout);
	buildPcapPacket(&pcapout);
	buildPcapData(&pcapout);
	
	
	printf("BEFORE BUILD ZERG HEADER\n");
	
	//OPEN FILE AND FILL INPUT FROM DATA FILE
	fp = updateZergHeader(&pcapout, fp);
	
	printf("After BUILD ZERG HEADER\n");
	
	//DECISION STRUCTURE FOR FILLING IN PAYLOAD STRUCTURE.
	fscanf(fp, "%s", string);
	printf("string: %s \n", string);
	for (int y = 0; y < strlen(string); y++)
	{
		if (string[y] == ':')
		{
			string[y] = '\0';
		}
	}
	printf("Position: %ld \n", ftell(fp));
	if (strcmp(string, "Message") == 0)
	{
		printf("Message length is %ld\n", filesize - ftell(fp));
		//Run Fill MSGPAYLOAD STRUCTURE
		fillMsgPayload(&pcapout, fp, filesize);
	} 
	else if ( strcmp(string, "Latitude") == 0 )
	{
		printf("Message length is %ld\n", filesize - ftell(fp));
		//Run Fill GPS DATA STRUCTURE
	}
	else if ( strcmp(string, "Name") == 0 )
	{
	//SET THE PAYLOAD TYPE IN ZERG HEADER
		//pcapout.pcapZerg.ver_type_totalLen = ((pcapout.pcapZerg.ver_type_totalLen >> 24) | 0x02);
		//printf("Zerg Payload type : %x \n", (pcapout.pcapZerg.ver_type_totalLen >> 24) & 0xff);
		printf("Message length is %ld\n", filesize - ftell(fp));
		//Run Fill STATUS STRUCTURE
		fillStatusPayload( &pcapout, fp, filesize);
	}
	else
	{
		printf("MIGHT BE A CMD\n");
		//GO TO FUNCTION TO EVALUATE IF INPUT == COMMAND
	}
	
	exit(1);	

	//MODIFY LENGTH SEGMENTS

	// OPEN FILE TO WRITE PCAP TO!!!
	fp = fopen(argv[2], "wb+");
	if (fp == NULL)
	{
		fprintf(stderr, "Could not open %s\n", argv[1]);
		exit(1);
	}
	printf("OUTPUT FILE IS OPEN\n");
	
	n = fwrite(&pcapout.fileHeader, 1, sizeof(struct filepcap), fp);
	printf("Printed bytes: %lu \n", n);
	
	n = fwrite(&pcapout.packetHeader, 1, sizeof(struct headerpcap), fp);
	printf("Printed bytes: %lu \n", n);
	
	n = fwrite(&pcapout.pcapFrame, 1, sizeof(struct etherFrame), fp);
	printf("Printed bytes: %lu \n", n);
	
	n = fwrite(&pcapout.pcapIpv4, 1, sizeof(struct ipv4Header), fp);
	printf("Printed bytes: %lu \n", n);
	
	n = fwrite(&pcapout.pcapUdp, 1, sizeof(struct udpHeader), fp);
	printf("Printed bytes: %lu \n", n);
	
	//Adjust the TOTAL LENGTH?
	
	n = fwrite(&pcapout.pcapZerg, 1, sizeof(struct zergHeader), fp);
	printf("Printed bytes: %lu \n", n);
	
	return 0;
}

void fillStatusPayload (struct zergPacket * pcap, FILE * fp, int filesize)
{
	printf("Inside Fill Status Payload\n");
	
	struct statusPayload test;
	char string[20], input[10];
	double maxSpeed;
	int hp, maxHp, armor, number;
	
	fscanf(fp, "%s", input);
	test.zergName = (char *) malloc(sizeof(char)* strlen(input));
	printf("Name: %s \n", input);
	
	while(fscanf(fp, "%s%s", string, input) == 2)
	{
		printf("String: %s \nInput: %s \n", string, input);	
		for (int y = 0; y < strlen(string); y++)
		{
			if (string[y] == ':')
			{
				string[y] = '\0';
			}
		}
		//printf("String: %s \nInput: %s \n", string, input);	
		if (strcmp(string, "HP") == 0)
		{
			printf("DOING STUFF WITH HP\n");
			sscanf(input, "%d/%d", &hp, &maxHp);
			printf("HP: %d | MaxHP: %d \n", hp, maxHp);
			
			test.hitPoints = (hp << 8) & test.hitPoints;
			printf("Hit Points: %08x \n", test.hitPoints);
			
			test.maxHitPoints = (maxHp << 8) | test.maxHitPoints;
			printf("Hit Points: %08x \n", test.maxHitPoints);
			
		}
		else if (strcmp(string, "Type") == 0)
		{
			printf("DOING STUFF WITH Type\n");
			number = getTypeNum(input);
			if (number == -1)
			{
				fprintf(stderr, "wrong type\n");
			}
			printf("TYPE: %d\n", number);
		}
		else if (strcmp(string, "Armor") == 0)
		{
			printf("DOING STUFF WITH Armor\n");
			armor = atoi(input);
			printf("ARMOR: %d \n", armor);
			//test.maxHitPoints = test.maxHitPoints | atoi(input);
		}
		else if (strcmp(string, "MaxSpeed") == 0)
		{
			printf("DOING STUFF WITH SPEED\n");
			input[7] = '\0';
			maxSpeed = atof(input);
			printf("SPEED: %f \n", maxSpeed);
			//convert float to binary32
			
		}
	}	
		
	pcap->output.status = test;
	
	return;
	
}

int getTypeNum(char * name)
{
	int sum = 0;
	
	for (int x = 0; x < strlen(name); x++)
	{
		printf("%c %d \n", name[x], sum);
		sum += name[x];
	}
	switch(sum)
	{
		case 836:
			printf("Overmind\n");
			return 0;
		case 502:
			printf("Larva\n");
			return 1;
		case 909:
			printf("Cerebrate\n");
			return 2;
		case 845:
			printf("Overlord\n");
			return 3;
		case 510:
			printf("Queen\n");
			return 4;
		case 504:
			printf("Drone\n");
			return 5;
		case 834:
			printf("Zergling\n");
			return 6;
		case 629:
			printf("Lurker\n");
			return 7;
		case 820:
			printf("Brooding\n");
			return 8;
		case 939:
			printf("Hydralisk\n");
			return 9;
		case 811:
			printf("Guardian\n");
			return 10;
		case 728:
			printf("Scourge\n");
			return 11;
		case 955:
			printf("Ultralisk\n");
			return 12;
		case 842:
			printf("Mutalisk\n");
			return 13;
		case 699:
			printf("Defiler\n");
			return 14;
		case 844:
			printf("Devourer\n");
			return 15;
		default:
			printf("Unknown\n");
			return -1;			
	}
}

void fillMsgPayload (struct zergPacket * pcap, FILE * fp, int filesize)
{
	int c, msgLength;
	struct msgPayload test;
	
	msgLength = filesize - ftell(fp);
	test.message = (char*)malloc(sizeof(char) * msgLength);
	for (int x = 0; x < msgLength; x++)
	{
		c = fgetc(fp);
		test.message[x] = c;
	}
	
	
	pcap->output.data = test;
	
	return;
}

FILE * updateZergHeader (struct zergPacket * pcap, FILE * fp)
{
	struct zergHeader zergtest;
	char string[20], input[10];
	uint32_t value;
	
	printf("INPUT FILE IS OPEN\n");
	for (int x = 0; x < 4; x++)
	{
		fscanf(fp, "%s %s", string, input);
		
		printf("%s %s\n", string, input);
		//Stripe off ':'.
		for (int y = 0; y < strlen(string); y++)
		{
			if (string[y] == ':')
			{
				string[y] = '\0';
			}
		}
		
		printf("String: [%s]\n", string);
		if (strcmp(string, "Version") == 0)
		{
			value = (atoi(input) << 28);
			printf("value:   %08x \n", value);
			printf("version: %08x \n", zergtest.ver_type_totalLen);
			zergtest.ver_type_totalLen = (value | zergtest.ver_type_totalLen);
			printf("version: %08x \n", zergtest.ver_type_totalLen);
			printf("Version in header: %x\n", zergtest.ver_type_totalLen >> 28);
			continue;
		}
		if (strcmp(string, "Sequence") == 0)
		{
			value = atoi(input);
			zergtest.seqID = ntohl(value);
			printf("SEQ ID in header: %x\n", zergtest.seqID);
			continue;
		}
		if (strcmp(string, "From") == 0)
		{
			value = atoi(input);
			zergtest.sourceID = ntohs(value);
			printf("SRC ID in header: %x\n", zergtest.sourceID);
			continue;
		}
		if (strcmp(string, "To") == 0)
		{
			value = atoi(input);
			zergtest.destID = ntohs(value);
			printf("DEST ID in header: %x\n", zergtest.destID);
			continue;
		}
	}
	printf("After FOR LOOP FOR VER/SEQ/FROM/TO\n");
	
	
	//After reading the input file completely. CLOSE IT.
	//fclose(fp);
	
	
	pcap->pcapZerg = zergtest;
	//pcap->pcap
	
	return fp;
}

void buildZergHeader (struct zergPacket * pcap)
{
	struct zergHeader zergtest;
	
	zergtest.ver_type_totalLen = ntohl(0x00000000);
	zergtest.sourceID = ntohs(0x0000);
	zergtest.destID = ntohs(0x0000);
	zergtest.seqID = ntohl(0x00000000);
	
	pcap->pcapZerg = zergtest;
	
	return;
}

void buildUdpHeader (struct zergPacket * pcap)
{
	struct udpHeader udptest;
	
	udptest.sport = ntohs(0x1111);
	udptest.dport = ntohs(0xCCCC);
	udptest.udpLen = ntohs(0x4444);
	udptest.udpChecksum = ntohs(0x0000);
	
	pcap->pcapUdp = udptest;
	
	return;
}



void buildIpHeader (struct zergPacket * pcap)
{
	struct ipv4Header iptest;
	
	iptest.ver_header = ntohs(0x4500);
	iptest.totalIPhdrlen = ntohs(0x0048);
	iptest.identification = ntohs(0x0000);
	iptest.flags_frags = ntohs(0x0000);
	iptest.nextProtocol = ntohs(0x0011);
	iptest.ipChecksum = ntohs(0x0000);
	iptest.srcAddroct1 = ntohl(0x0a00144f);
	iptest.srcAddroct2 = ntohl(0xffffffff);
	
	pcap->pcapIpv4 = iptest;
	
	return;
}

void buildEtherFrame (struct zergPacket * pcap)
{
	struct etherFrame ethertest;

	for (int x = 0; x < 6; x++)
	{
		ethertest.destMac[x] = 0xFF;
	}
	for (int x = 0; x < 6; x++)
	{
		ethertest.srcMac[x] = 0xDD;
	}
	ethertest.etherType = ntohs(0x0800);
	
	
	pcap->pcapFrame = ethertest;
	
}

void buildPcapPacket(struct zergPacket * pcap)
{
	struct headerpcap headertest;
	
	headertest.unixEpoch = ntohl(0x00400040);
	headertest.microsec = ntohl(0x00000000);
	headertest.dataCapture = ntohl(0x00000000);
	headertest.trunPacketLen = ntohs(0x0000);
	
	pcap->packetHeader  = headertest;
	

	return;
}
void buildPcapData(struct zergPacket * pcap)
{
	struct filepcap filetest;
	
	printf("Opened the FILE!\n");
	
	filetest.fileTypeID = ntohl(0xd4c3b2a1);
	filetest.majorVersion = ntohs(0x0200);
	filetest.minorVersion = ntohs(0x0400);
	filetest.gmtOffset = ntohl(0x000000000);
	filetest.accuracyDelta = ntohl(0x00000000);
	filetest.maxLengthCapture = ntohl(0x00000100);
	filetest.linkLayerType = ntohl(0x01000000);

	pcap->fileHeader = filetest;
	
	return;
}
