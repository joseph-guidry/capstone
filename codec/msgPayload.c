#include "decode.h"

FILE * printMsgPayload (struct zergPacket * pcapfile, FILE *fp)
{
	struct msgPayload pcap;
	int msgLength;
	int c;
	
	msgLength = ((htonl(pcapfile->pcapZerg.ver_type_totalLen) & 0xffffff) - 12);
	if (msgLength <= 0)
	{
		fprintf(stderr, "No message available\n");
		return fp;
	}
	pcap.message = (char *) malloc (msgLength * sizeof(char));
	if ( pcap.message == NULL)
	{
		fprintf(stderr, "Not enough memory\n");
		exit(1);
	}
	
	for (int x = 0; x < msgLength; x++)
	{
		c = fgetc(fp);
		if ( (c == EOF) )
		{
			break;
		}
		pcap.message[x] = c;
	}
	printf("Message: %s\n", pcap.message);
	free(pcap.message);
	return fp;
}
