#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "decode.h"

FILE * buildPcapData(struct zergPacket * pcap, char * filename);

int main(int argc, char **argv)
{
	FILE *fp;
	struct zergPacket pcapfile;
	int msgLength;
	int c;
	char filename[25];
	strcpy(filename, argv[1]);
	
	fp = buildPcapData(&pcapfile, filename);
	//n = fread(&pcapfile, 1, sizeof(struct zergPacket), fp);
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
	printf("Zerg total Length: %x \n", htonl(pcapfile.pcapZerg.ver_type_totalLen) & 0xfffff);
	printf("Zerg dest ID: %d \n", htons(pcapfile.pcapZerg.destID));
	printf("Zerg src ID: %d \n", htons(pcapfile.pcapZerg.sourceID));
	
	msgLength = ((htonl(pcapfile.pcapZerg.ver_type_totalLen) & 0xfffff) - sizeof(struct zergHeader));
	printf("msgLength: %d\n", msgLength);
	
	for (int x = 0; x < msgLength; x++)
	{
		c = fgetc(fp);
		if (c == EOF)
		{
			break;
		}
		putchar(c);
	}
	putchar('\n');
	fclose(fp);
	

	return 0;
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
