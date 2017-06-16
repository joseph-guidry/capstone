#include "decode.h"

FILE * printStatusPayload (struct zergPacket * pcapfile, FILE *fp)
{
	struct statusPayload pcap;
	int c, msgLength;
	double zergSpeed;
	char zergType[15];
	
	// Position prior to reading status payload header.
	fread(&pcap, 1, 12, fp);  
	msgLength = ((htonl(pcapfile->pcapZerg.ver_type_totalLen) & 0xfffff) - 12);
	if (msgLength <= 0)
	{
		fprintf(stderr, "No message available\n");
		return fp;
	}
	msgLength = msgLength - 12;
	//Get STATUS PAYLOAD NAME
	pcap.zergName = (char *) malloc (msgLength * sizeof(char));
	if ( pcap.zergName == NULL)
	{
		fprintf(stderr, "Not enough memory\n");
		exit(1);
	}
	for (int x = 0; x < msgLength; x++)
	{
		c = fgetc(fp);
		if ( (c == EOF) || (c == '\n') )
		{
			break;
		}
		
		pcap.zergName[x] = c;
	}
	printf("Name: %s \n", pcap.zergName);
	printf("HP: %u/%u\n",(htonl(pcap.hitPoints) >> 8), (htonl(pcap.maxHitPoints) >> 8) );
	getZergType(zergType, (htonl(pcap.maxHitPoints) & 0xff));
	printf("Type: %s \n" ,zergType);
	printf("Armor: %x \n", htonl(pcap.hitPoints) & 0xff);
	zergSpeed = convertBin32toDecimal(htonl(pcap.speed) & 0x7fffffff);
	printf("MaxSpeed: %.4fm/s\n", zergSpeed);
	free(pcap.zergName);
	return fp; 
}

void getZergType(char * test, int x)
{
	switch (x)
	{
		case 0:
			strcpy(test, "Overmind");
			break;
		case 1:
			strcpy(test, "Larva");
			break;
		case 2:
			strcpy(test, "Cerebrate");
			break;
		case 3:
			strcpy(test, "Overlord");
			break;
		case 4:
			strcpy(test, "Queen");
			break;
		case 5:
			strcpy(test, "Drone");
			break;
		case 6:
			strcpy(test, "Zergling");
			break;
		case 7:
			strcpy(test, "Lurker");
			break;
		case 8:
			strcpy(test, "Broodling");
			break;
		case 9:
			strcpy(test, "Hydralisk");
			break;
		case 10:
			strcpy(test, "Guardian");
			break;
		case 11:
			strcpy(test, "Scourge");
			break;
		case 12:
			strcpy(test, "Ultralisk");
			break;
		case 13:
			strcpy(test, "Mutalisk");
			break;
		case 14:
			strcpy(test, "Defiler");
			break;
		case 15:
			strcpy(test, "Devourer");
			break;
		default:
			printf("Unknown Type\n");
			break;
	}
}
