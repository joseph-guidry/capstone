#include "encode.h"

uint16_t buildIpHeader (struct zergPacket * pcap)
{
	unsigned short headerLength = 20;
	uint16_t ipType;
	
	ipType = htons(pcap->pcapFrame.etherType);
	if (ipType == 0x0800)
	{
		fillIpv4(pcap);
	}
	else if (ipType == 0x08DD)
	{
		fillIpv6(pcap);
		headerLength = 40;
	}
	return headerLength;
	
}
void fillIpv6 (struct zergPacket * pcap)
{
	struct ipv6Header iptest;
	
	iptest.ver_class_flowLabel = ntohl(0x12345678);
	iptest.payloadLen_nxtHdr_HopLimit = ntohl(0xABCDEF01);
	
	for (int x = 0; x < 16; x++)
	{
		iptest.srcAddress[x] = 0xFF;
		iptest.destAddress[x] = 0xDD;
	}
	
	pcap->pcapIp.ipv6 = iptest;
	
	return;
}

void fillIpv4(struct zergPacket * pcap)
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
	
	pcap->pcapIp.ipv4 = iptest;
	
	return;
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
		for (int y = 0; y < strlen(string); y++)
		{
			if (string[y] == ':')
			{
				string[y] = '\0';
			}
		}
		if (strcmp(string, "Version") == 0)
		{
			value = (atoi(input) << 28);
			zergtest.ver_type_totalLen = (value & zergtest.ver_type_totalLen) & 0xF0000000;
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


void buildEtherFrame (struct zergPacket * pcap)
{
	struct etherFrame ethertest;

	for (int x = 0; x < 6; x++)
	{
		ethertest.destMac[x] = 0xFF;
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
