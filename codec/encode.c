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


