#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <math.h>
#include <inttypes.h>
#include "codec.h"

void buildPcapData (struct zergPacket * pcap);
void buildPcapPacket (struct zergPacket * pcap);
void buildEtherFrame (struct zergPacket * pcap);
void buildIpHeader (struct zergPacket * pcap);
void buildUdpHeader (struct zergPacket * pcap);
void buildZergHeader (struct zergPacket * pcap, char * filename);

int main(int argc, char **argv)
{
	FILE * fp;
	unsigned long n;
	struct zergPacket pcapout;
	
	printf("Filling PCAP!\n");
	buildPcapData(&pcapout);
	buildPcapPacket(&pcapout);
	buildEtherFrame(&pcapout);
	buildIpHeader(&pcapout);
	buildUdpHeader(&pcapout);
	
	//OPEN FILE AND FILL INPUT FROM DATA FILE
	buildZergHeader(&pcapout, argv[1]);
	
	
	
	
	
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
	
	return 0;
}

void buildZergHeader (struct zergPacket * pcap, char * filename)
{
	FILE *fp;
	struct zergHeader zergtest;
	char string[20], input[10];
	uint32_t value, filesize;
	//zergtest.ver_type_totalLen = ntohl(0x10000048);
	//zergtest.sourceID = ntohs(0x0539);
	//zergtest.destID = ntohs(0x19c8);
	//zergtest.seqID = ntohl(0x00013370);
	
	fp = fopen(filename, "r");
	if (fp == NULL)
	{
		fprintf(stderr, "Could not open %s\n", filename);
		exit(1);
	}
	fseek(fp, 0, 2);
	filesize = ftell(fp);
	printf("Filesize: %u\n", filesize);
	fseek(fp, 0, 0);
	
	printf("INPUT FILE IS OPEN\n");
	for (int x = 0; x < 4; x++)
	{
		fscanf(fp, "%s %s", string, input);
		
		printf("%s %s\n", string, input);
		
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
			zergtest.ver_type_totalLen = ntohl(value & (zergtest.ver_type_totalLen << 28));
			printf("Version in header: %x\n", zergtest.ver_type_totalLen << 28);
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
	}
	
	//After reading the input file completely. CLOSE IT.
	fclose(fp);
	
	
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
	
	printf("here: %lu \n", sizeof(struct etherFrame));
	
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
