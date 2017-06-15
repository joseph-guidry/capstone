#include "decode.h"

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
