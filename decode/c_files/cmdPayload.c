#include "decode.h"

FILE * printCmdPayload (FILE *fp)
{
	struct commandPayload pcap;
	uint16_t param1;
	uint32_t param2;
	int command;
	
	fread(&pcap, 1, 2, fp);
	command = htons(pcap.command);
	
	if ((command % 2) == 1)
	{
		fread(&pcap.parameter1, 1, 2, fp);
		fread(&pcap.parameter2, 1, 4, fp);
	}
	
	switch (command) 
	{
		case 0:
			printf("GET_STATUS\n");
			break;
		case 1:
			param1 = htons(pcap.parameter1);
			param2 = htonl(pcap.parameter2);
			printf("GO_TO %d %.1f\n", param1, convertBin32toDecimal(param2));
			break;
		case 2:
			printf("GET_GPS\n");
			break;
		case 3:
			printf("RESERVED\n");
			break;
		case 4:
			printf("RETURN\n");
			break;
		case 5:
			param1 = htons(pcap.parameter1);
			param2 = htonl(pcap.parameter2);
			printf("SET_GROUP %d %s\n", param2, (param1 == 1)? "ADD": "REMOVE");
			break;
		case 6:
			printf("STOP\n");
			break;
		case 7:
			param1 = htons(pcap.parameter1);
			param2 = htonl(pcap.parameter2);
			printf("REPEAT %u\n", param2);
			break;
		default:
			printf("Unknown\n");
			break;
	}
	return fp;
}
