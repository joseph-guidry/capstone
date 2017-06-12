#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <math.h>
#include <inttypes.h>
#include "codec.h"

unsigned long fillMsgPayload (struct zergPacket * pcap, FILE * fp, int filesize);
unsigned long fillStatusPayload (struct zergPacket * pcap, FILE * fp, int filesize);
unsigned long fillGpsPayload (struct zergPacket * pcap, FILE * fp, int filesize);

uint64_t swapLong( uint64_t x);

int getTypeNum(char * name);
uint32_t convertToBinary(int number, float decimal);

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
	unsigned long n, filesize, payloadSize;
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
	
	
	printf("BEFORE UPDATE ZERG HEADER\n");
	
	//OPEN FILE AND FILL INPUT FROM DATA FILE
	fp = updateZergHeader(&pcapout, fp);
	
	printf("TO: %x\nFROM: %x\n", pcapout.pcapZerg.sourceID, pcapout.pcapZerg.destID);
	
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
		printf("%lu %lu \n", filesize, ftell(fp));
		printf("Message length is %ld\n", filesize - ftell(fp));
		pcapout.pcapZerg.ver_type_totalLen = ntohl((0 << 24) | pcapout.pcapZerg.ver_type_totalLen );
		//Run Fill MSGPAYLOAD STRUCTURE
		payloadSize = fillMsgPayload(&pcapout, fp, filesize);
		printf("Payload Size: %lu \n", payloadSize);
		printf("Message: %s\n", pcapout.output.data.message);
	} 
	else if ( strcmp(string, "Latitude") == 0 )
	{
		printf("Message length is %ld\n", filesize - ftell(fp));
		pcapout.pcapZerg.ver_type_totalLen = ntohl((3 << 24) | pcapout.pcapZerg.ver_type_totalLen) ;
		printf("\nVers: %x \nType: %x \n\n",pcapout.pcapZerg.ver_type_totalLen >>28, pcapout.pcapZerg.ver_type_totalLen >> 24 );
		//Run Fill GPS DATA STRUCTURE
		payloadSize = fillGpsPayload(&pcapout, fp, filesize);
		printf("Payload Size: %lu \n", payloadSize);
	}
	else if ( strcmp(string, "Name") == 0 )
	{
		pcapout.pcapZerg.ver_type_totalLen = ntohl((1 << 24) | pcapout.pcapZerg.ver_type_totalLen);
		printf("Type: %04x \n", pcapout.pcapZerg.ver_type_totalLen);
		printf("Message length is %ld\n", filesize - ftell(fp));
		
		//Run Fill STATUS STRUCTURE
		payloadSize = fillStatusPayload( &pcapout, fp, filesize);
	}
	else
	{
		printf("MIGHT BE A CMD\n");
		pcapout.pcapZerg.ver_type_totalLen = ntohl((2 << 24) | pcapout.pcapZerg.ver_type_totalLen );
		//GO TO FUNCTION TO EVALUATE IF INPUT == COMMAND
	}
	
	//UPDATE ZERG HEADER LENGTH
	pcapout.pcapZerg.ver_type_totalLen = (pcapout.pcapZerg.ver_type_totalLen & 0x00FFFFFF); 
	pcapout.pcapZerg.ver_type_totalLen = ntohl(ntohl(pcapout.pcapZerg.ver_type_totalLen) + 12 + payloadSize);
	printf("Payload Size: %lu %lx \n", payloadSize, payloadSize);

	//UPDATE UDP HEADER LENGTH
	pcapout.pcapUdp.udpLen = pcapout.pcapUdp.udpLen & 0x0000;
	pcapout.pcapUdp.udpLen = ntohs(pcapout.pcapUdp.udpLen + 20 + payloadSize);
	
	//UPDATE IPV4 HEADER LENGTH
	pcapout.pcapIpv4.totalIPhdrlen = pcapout.pcapIpv4.totalIPhdrlen & 0x0000;
	pcapout.pcapIpv4.totalIPhdrlen = ntohs(pcapout.pcapIpv4.totalIPhdrlen + 12 + 8 + 20 + payloadSize);
	
	//UPDATE pcap PACKET HEADER 
	pcapout.packetHeader.dataCapture = pcapout.packetHeader.dataCapture & 0x00000000;
	pcapout.packetHeader.dataCapture = ntohl(pcapout.packetHeader.dataCapture + 14 + 12 + 8 + 20 + payloadSize);

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
	
	n = fwrite(&pcapout.pcapZerg, 1, sizeof(struct zergHeader), fp);
	printf("Printed bytes: %lu \n", n);
	
	n = fwrite(&pcapout.output.data, 1, payloadSize, fp);
	printf("Printed bytes: %lu \n", n);
	
	return 0;
}
unsigned long fillGpsPayload (struct zergPacket * pcap, FILE * fp, int filesize)
{
	struct gpsDataPayload test;
	printf("Inisde Fill GPS Payload\n");
	printf("Position: %lu \n", ftell(fp));
	
	char coordinates[60], string[20], input[10], trash[5];
	char direction;
	
	//Get the value after Latitude: 
	fgets(coordinates, 50, fp);
	sscanf(coordinates, "%s %s %s", input, trash, &direction);
	printf("Latitude: %s %c\n", input, direction);
	test.latitude.value = atof(input) * ( (direction == 'E'? -1 : 1) );
	printf("Latitude in Binary64: %lx \n", test.latitude.value64);
	test.latitude.value64 = swapLong(test.latitude.value64);
	
	printf("Position: %lu \n", ftell(fp));
	
	fgets(coordinates, 60, fp);
	sscanf(coordinates, "%s %s %s %s", string, input, trash, &direction);
	printf("First Line: %s %s %s %s\n", string, input, trash, &direction);
	test.longitude.value = atof(input) * ( (direction == 'S'? -1 : 1) );
	printf("Longitude in Binary64: %lx \n", test.longitude.value64);
	test.longitude.value64 = swapLong(test.longitude.value64);
	
	fgets(coordinates, 60, fp);
	sscanf(coordinates, "%s %s", string, input);
	test.altitude.value = (atof(input) /1.8288);
	printf("Altitude Line: %s %s\n", string, input);
	printf("Altitude Line: %s %.4f\n", string, test.altitude.value);
	test.altitude.value32 = ntohl(test.altitude.value32);
	
	fgets(coordinates, 60, fp);
	sscanf(coordinates, "%s %s", string, input);
	test.bearing.value = atof(input);
	printf("Bearing Line: %s %s\n", string, input);
	printf("Bearing Line: %s %.4f\n", string, test.bearing.value);
	test.bearing.value32 = ntohl(test.bearing.value32);
	
	fgets(coordinates, 60, fp);
	sscanf(coordinates, "%s %s", string, input);
	test.speed.value = (atof(input) / 3.6);
	printf("Speed Line: %s %s\n", string, input);
	printf("Speed Line: %s %.4f\n", string, test.speed.value);
	printf("Speed Line: %s %x\n", string, test.speed.value32);
	test.speed.value32 = ntohl(test.speed.value32);
	
	fgets(coordinates, 60, fp);
	sscanf(coordinates, "%s %s", string, input);
	test.accuracy.value = atof(input);
	printf("Accuracy Line: %s %s\n", string, input);
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

unsigned long fillStatusPayload (struct zergPacket * pcap, FILE * fp, int filesize)
{
	printf("Inside Fill Status Payload\n");
	
	struct statusPayload test;
	char string[20], input[10];
	double maxSpeed;
	int hp, maxHp, armor, number; 
	
	fscanf(fp, "%s", input);
	printf("Name: %s \n", input);
	strcpy(test.zergName, input);
	
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
		printf("String: %s \nInput: %s \n", string, input);	
		if (strcmp(string, "HP") == 0)
		{
			printf("DOING STUFF WITH HP\n");
			sscanf(input, "%d/%d", &hp, &maxHp);
			printf("HP: %d | MaxHP: %d \n", hp, maxHp);
			test.hitPoints = test.maxHitPoints = 0x00000000;
			test.hitPoints = ntohl((test.hitPoints  | hp) << 8 );
			printf("Hit Points: %04x \n", test.hitPoints);
			
			test.maxHitPoints = (maxHp << 8) | test.maxHitPoints;
			printf("Max Hit Points: %04x \n", test.maxHitPoints);
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
			test.maxHitPoints &= 0xffffff00;
			test.maxHitPoints |= number;
			printf("Hit Points: %08x \n", test.maxHitPoints);
			test.maxHitPoints = ntohl(test.maxHitPoints);
		}
		else if (strcmp(string, "Armor") == 0)
		{
			printf("DOING STUFF WITH Armor\n");
			armor = atoi(input);
			printf("ARMOR: %d \n", armor);
			test.hitPoints &= 0xffffff00;
			test.hitPoints |= armor;
			printf("Hit Points: %08x \n", test.hitPoints);
		}
		else if (strcmp(string, "MaxSpeed") == 0)
		{
			printf("DOING STUFF WITH SPEED\n");
			input[strlen(input) - 3] = '\0';
			maxSpeed = atof(input);
			printf("SPEED: %f \n", maxSpeed);
			test.speed.value = maxSpeed;
			printf("Binary Speed: %04x \n", test.speed.value32);
			test.speed.value32 = htonl(test.speed.value32);
		}
	}	
		
	pcap->output.status = test;
	return 12 + strlen(pcap->output.status.zergName);
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

unsigned long fillMsgPayload (struct zergPacket * pcap, FILE * fp, int filesize)
{
	int c, msgLength;
	struct msgPayload test;
	printf("Inside fillMsgPayload\n");
	msgLength = filesize - ftell(fp);
	printf("MsgLength: %d \n", msgLength);
	
	//test.message = (char*)malloc(sizeof(char) * msgLength);
	if ( (c = fgetc(fp)) == ' ')
	{
		;
	}
	else
	{
		ungetc(c, fp);
	}
	for (int x = 0; x < msgLength - 2; x++)
	{
		c = fgetc(fp);
		printf("%c", c);
		test.message[x] = c;
	}
	
	pcap->output.data = test;
	
	printf("Size of payload: %lu \n", strlen(pcap->output.data.message));
	
	return strlen(pcap->output.data.message) - 1;
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
			zergtest.ver_type_totalLen = value | zergtest.ver_type_totalLen;
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
