#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <math.h>
#include <inttypes.h>
#include "encode.h"

int main(int argc, char **argv)
{
	FILE * fp, * foutp;
	char string[20];
	unsigned long filesize, payloadSize;
	struct zergPacket pcapout;
	if (argc > 3)
	{
		fprintf(stderr, "%s: usage error\n", argv[0]);
		exit(1);
	}	
	fp = fopen(argv[1], "r");
	if (fp == NULL)
	{
		fprintf(stderr, "Could not open %s\n", argv[1]);
		exit(1);
	}
	fseek(fp, 0, 2);
	filesize = ftell(fp);
	fseek(fp, 0, 0);
	
	foutp = fopen(argv[2], "wb+");
	if (foutp == NULL)
	{
		fprintf(stderr, "Could not open %s\n", argv[1]);
		exit(1);
	}
	
	//Complete After zergHeader/Payload modifications
	buildPcapData(&pcapout);
	
	fwrite(&pcapout.fileHeader, 1, sizeof(struct filepcap), foutp);
	while( (unsigned int)ftell(fp) + 1 < filesize)
	{
		buildPcapPacket(&pcapout);
		buildEtherFrame(&pcapout);
		buildIpHeader(&pcapout);
		buildUdpHeader(&pcapout);
		buildZergHeader(&pcapout);
	
		//OPEN FILE AND FILL INPUT FROM DATA FILE
		fp = updateZergHeader(&pcapout, fp);

		//DECISION STRUCTURE FOR FILLING IN PAYLOAD STRUCTURE.
		fscanf(fp, "%s", string);
		for (unsigned int y = 0; y < strlen(string); y++)
		{
			if (string[y] == ':')
			{
				string[y] = '\0';
			}
		}
			
		if (strcmp(string, "Message") == 0)
		{
			pcapout.pcapZerg.ver_type_totalLen = ntohl((0 << 24) | pcapout.pcapZerg.ver_type_totalLen );
			//Run Fill MSGPAYLOAD STRUCTURE
			payloadSize = fillMsgPayload(&pcapout, fp, filesize);
			
		} 
		else if ( strcmp(string, "Latitude") == 0 )
		{
			pcapout.pcapZerg.ver_type_totalLen = ntohl((3 << 24) | pcapout.pcapZerg.ver_type_totalLen) ;
			//Run Fill GPS DATA STRUCTURE
			payloadSize = fillGpsPayload(&pcapout, fp);
		}
		else if ( strcmp(string, "Name") == 0 )
		{
			pcapout.pcapZerg.ver_type_totalLen = ntohl((1 << 24) | pcapout.pcapZerg.ver_type_totalLen);
			//Run Fill STATUS STRUCTURE
			payloadSize = fillStatusPayload( &pcapout, fp);
		}
		else
		{
			pcapout.pcapZerg.ver_type_totalLen = ntohl( ((2 << 24) | pcapout.pcapZerg.ver_type_totalLen) & 0xFF000000 );
			payloadSize = fillCmdPayload(&pcapout, fp, string);
		}
		
		//UPDATE ZERG HEADER LENGTH
		pcapout.pcapZerg.ver_type_totalLen = ntohl(ntohl(pcapout.pcapZerg.ver_type_totalLen) + 12 + payloadSize);

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
		fwrite(&pcapout.packetHeader, 1, sizeof(struct headerpcap), foutp);
		fwrite(&pcapout.pcapFrame, 1, sizeof(struct etherFrame), foutp);
		fwrite(&pcapout.pcapIpv4, 1, sizeof(struct ipv4Header), foutp);
		fwrite(&pcapout.pcapUdp, 1, sizeof(struct udpHeader), foutp);
		fwrite(&pcapout.pcapZerg, 1, sizeof(struct zergHeader), foutp);
		fwrite(&pcapout.output.data, 1, payloadSize, foutp);
	}

	fclose(fp);
	fclose(foutp);
	return 0;
}

unsigned long fillCmdPayload( struct zergPacket * pcap, FILE * fp, char * commandName)
{
	int optionLength = 0;
	char input[10];
	struct commandPayload test;
	if (strcmp(commandName, "GET_STATUS") == 0)
	{
		test.command = ntohs(0x00);
		optionLength += 2;
	}
	else if (strcmp(commandName, "GO_TO") == 0)
	{
		test.command = ntohs(0x01);
		fscanf(fp, "%s", input);
		test.parameter1 = ntohs(atoi(input));
		fscanf(fp, "%s", input);
		test.parameter2.value = atof(input);
		test.parameter2.value32 = ntohl(test.parameter2.value32);
		optionLength += 8; 
	}
	else if (strcmp(commandName, "GET_GPS") == 0)
	{
		test.command = ntohs(0x02);
		optionLength += 2;
	}
	else if (strcmp(commandName, "RESERVED") == 0)
	{
		test.command = ntohs(0x03);
		optionLength += 2; 
	}
	else if (strcmp(commandName, "RETURN") == 0)
	{
		test.command = ntohs(0x04);
		optionLength += 2;
	}
	else if (strcmp(commandName, "SET_GROUP") == 0)
	{
		test.command = ntohs(0x05);
		fscanf(fp, "%s", input);
		if (strcmp(input, "ADD") == 0)
		{
			test.parameter1 = ntohs(0x01);
		}
		else
		{
			test.parameter1 = 0x00;	
		}
		fscanf(fp, "%s", input);
		test.parameter2.value32 = atoi(input);
		test.parameter2.value32 = ntohl(test.parameter2.value32);
		optionLength += 8; 
	}
	else if (strcmp(commandName, "STOP") == 0)
	{
		test.command = ntohs(0x06);
		optionLength += 2;
	}
	else if (strcmp(commandName, "REPEAT") == 0)
	{
		test.command = ntohs(0x07);
		test.parameter1 = ntohs(0x00);
		test.parameter2.value32 = pcap->pcapZerg.seqID;
		optionLength += 8; 
	}
	else
	{
		test.command = 0xFF;           //UNKNOWN COMMAND TYPE
		optionLength += 2;
	}
	
	pcap->output.command = test;

	return optionLength;
}

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

unsigned long fillStatusPayload (struct zergPacket * pcap, FILE * fp)
{
	struct statusPayload test;
	char string[20], input[10];
	double maxSpeed;
	int hp, maxHp, armor, number; 
	
	fscanf(fp, "%s", input);
	strcpy(test.zergName, input);
	printf("%s \n", input);
	while(fscanf(fp, "%s%s", string, input) == 2)
	{
		printf("%s %s\n", string, input);
		for (unsigned int y = 0; y < strlen(string); y++)
		{
			if (string[y] == ':')
			{
				string[y] = '\0';
			}
		}
		if (strcmp(string, "HP") == 0)
		{
			sscanf(input, "%d/%d", &hp, &maxHp);
			test.hitPoints = test.maxHitPoints = 0x00000000;
			test.hitPoints = ntohl((test.hitPoints  | hp) << 8 );
			test.maxHitPoints = (maxHp << 8) | test.maxHitPoints;
		}
		else if (strcmp(string, "Type") == 0)
		{
			number = getTypeNum(input);
			if (number == -1)
			{
				fprintf(stderr, "wrong type\n");
			}
			test.maxHitPoints &= 0xffffff00;
			test.maxHitPoints |= number;
			test.maxHitPoints = ntohl(test.maxHitPoints);
		}
		else if (strcmp(string, "Armor") == 0)
		{
			armor = atoi(input);
			test.hitPoints &= 0xffffff00;
			test.hitPoints |= armor;
		}
		else if (strcmp(string, "MaxSpeed") == 0)
		{
			input[strlen(input) - 3] = '\0';
			maxSpeed = atof(input);
			test.speed.value = maxSpeed;
			test.speed.value32 = htonl(test.speed.value32);
		}
	}	
		
	pcap->output.status = test;
	return 12 + strlen(pcap->output.status.zergName);
}

int getTypeNum(char * name)
{
	int sum = 0;
	
	for (unsigned int x = 0; x < strlen(name); x++)
	{
		sum += name[x];
	}
	switch(sum)
	{
		case 836:
			return 0;
		case 502:
			return 1;
		case 909:
			return 2;
		case 845:
			return 3;
		case 510:
			return 4;
		case 504:
			return 5;
		case 834:
			return 6;
		case 629:
			return 7;
		case 820:
			return 8;
		case 939:
			return 9;
		case 811:
			return 10;
		case 728:
			return 11;
		case 955:
			return 12;
		case 842:
			return 13;
		case 699:
			return 14;
		case 844:
			return 15;
		default:
			return -1;			
	}
}

unsigned long fillMsgPayload (struct zergPacket * pcap, FILE * fp, int filesize)
{
	int c, msgLength;
	struct msgPayload test;
	msgLength = filesize - ftell(fp);
	if ( (c = fgetc(fp)) == ' ')
	{
		;
	}
	else
	{
		ungetc(c, fp);
	}
	for (int x = 0; x < msgLength -1; x++)
	{
		c = fgetc(fp);
		test.message[x] = c;
	}
	pcap->output.data = test;
	
	return msgLength - 1;
}

FILE * updateZergHeader (struct zergPacket * pcap, FILE * fp)
{
	struct zergHeader zergtest;
	char string[20], input[10];
	uint32_t value;
	
	for (int x = 0; x < 4; x++)
	{
		fscanf(fp, "%s %s", string, input);
		
		//Stripe off ':'.
		for (unsigned int y = 0; y < strlen(string); y++)
		{
			if (string[y] == ':')
			{
				string[y] = '\0';
			}
		}
		if (strcmp(string, "Version") == 0)
		{
			value = (atoi(input) << 28);
			zergtest.ver_type_totalLen = (value | zergtest.ver_type_totalLen) & 0xF0000000;
			continue;
		}
		if (strcmp(string, "Sequence") == 0)
		{
			value = atoi(input);
			zergtest.seqID = ntohl(value);
			continue;
		}
		if (strcmp(string, "From") == 0)
		{
			value = atoi(input);
			zergtest.sourceID = ntohs(value);
			continue;
		}
		if (strcmp(string, "To") == 0)
		{
			value = atoi(input);
			zergtest.destID = ntohs(value);
			continue;
		}
	}
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
	
	headertest.unixEpoch = ntohl(0xABCDABCD);
	headertest.microsec = ntohl(0x00000000);
	headertest.dataCapture = ntohl(0x00000000);
	headertest.trunPacketLen = ntohs(0x0000);
	
	pcap->packetHeader  = headertest;

	return;
}
void buildPcapData(struct zergPacket * pcap)
{
	struct filepcap filetest;
	
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
