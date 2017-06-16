#include "decode.h"

int main (int argc, char **argv)
{
	FILE *fp;
	struct zergPacket pcapfile;
	int msgType, filesize, sum;
	char filename[25];
	if (argc > 2)
	{
		fprintf(stderr, "%s: usage error < input file >\n", argv[0]);
		exit(1);
	}
	//Fill pcap structure with individual header structures.
	strcpy(filename, argv[1]);
	
	fp = buildPcapData(&pcapfile, filename, &filesize);
	
	while((ftell(fp) < filesize) && ((filesize - ftell(fp)) > 60))
	{
		fp = buildPacketData(&pcapfile, fp);
		printf("Version: %x \n", htonl(pcapfile.pcapZerg.ver_type_totalLen) >> 28);
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
