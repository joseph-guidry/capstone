#include "encode.h"

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
