#include "encode.h"

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
