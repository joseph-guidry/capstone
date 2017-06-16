#include "encode.h"

unsigned long fillCmdPayload( struct zergPacket * pcap, FILE * fp, int filesize, char * commandName)
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
		printf("UNKNOWN\n");
		test.command = 0xFF;           //UNKNOWN COMMAND TYPE
		optionLength += 2;
	}
	
	pcap->output.command = test;
	
	return optionLength;
	
}

unsigned long fillGpsPayload (struct zergPacket * pcap, FILE * fp, int filesize)
{
	struct gpsDataPayload test;
	char coordinates[60], string[20], input[10], trash[5];
	char direction;
	
	fgets(coordinates, 50, fp);
	sscanf(coordinates, "%s %s %s", input, trash, &direction);
	test.latitude.value = atof(input) * ( (direction == 'E'? -1 : 1) );
	test.latitude.value64 = swapLong(test.latitude.value64);
	
	fgets(coordinates, 60, fp);
	sscanf(coordinates, "%s %s %s %s", string, input, trash, &direction);
	test.longitude.value = atof(input) * ( (direction == 'S'? -1 : 1) );
	test.longitude.value64 = swapLong(test.longitude.value64);
	
	fgets(coordinates, 60, fp);
	sscanf(coordinates, "%s %s", string, input);
	test.altitude.value = (atof(input) /1.8288);
	test.altitude.value32 = ntohl(test.altitude.value32);
	
	fgets(coordinates, 60, fp);
	sscanf(coordinates, "%s %s", string, input);
	test.bearing.value = atof(input);
	test.bearing.value32 = ntohl(test.bearing.value32);
	
	fgets(coordinates, 60, fp);
	sscanf(coordinates, "%s %s", string, input);
	test.speed.value = (atof(input) / 3.6);
	test.speed.value32 = ntohl(test.speed.value32);
	
	fgets(coordinates, 60, fp);
	sscanf(coordinates, "%s %s", string, input);
	test.accuracy.value = atof(input);
	test.accuracy.value32 = ntohl(test.accuracy.value32);
	
	pcap->output.gps = test;
	
	return 32;  //Number of bytes in GPS Payload.
}

uint64_t swapLong( uint64_t x)
{
	x = ((x << 8 ) & 0xFF00FF00FF00FF00ULL)  | ((x >> 8)  &  0x00FF00FF00FF00FFULL);
	x = ((x << 16 ) &  0xFFFF0000FFFF0000ULL) | ((x >> 16) &  0x0000FFFF0000FFFFULL);
	
	return (x << 32) | (x >> 32);
}

unsigned long fillStatusPayload (struct zergPacket * pcap, FILE * fp, int filesize)
{
	struct statusPayload test;
	char string[20], input[10];
	double maxSpeed;
	int hp, maxHp, armor, number; 
	
	fscanf(fp, "%s", input);
	strcpy(test.zergName, input);
	
	while(fscanf(fp, "%s%s", string, input) == 2)
	{
		for (int y = 0; y < strlen(string); y++)
		{
			if (string[y] == ':')
			{
				string[y] = '\0';
			}
		}
		if (strcmp(string, "HP") == 0)
		{
			sscanf(input, "%d/%d", &hp, &maxHp);
			test.hitPoints = test.maxHitPoints = 0x00000000;
			test.hitPoints = ntohl((test.hitPoints  | hp) << 8 );
			test.maxHitPoints = (maxHp << 8) | test.maxHitPoints;
		}
		else if (strcmp(string, "Type") == 0)
		{
			number = getTypeNum(input);
			if (number == -1)
			{
				fprintf(stderr, "wrong type: %s %d\n", string, number);
				continue;
			}
			test.maxHitPoints &= 0xffffff00;
			test.maxHitPoints |= number;
			test.maxHitPoints = ntohl(test.maxHitPoints);
		}
		else if (strcmp(string, "Armor") == 0)
		{
			armor = atoi(input);
			test.hitPoints &= 0xffffff00;
			test.hitPoints |= armor;
		}
		else if (strcmp(string, "MaxSpeed") == 0)
		{
			input[strlen(input) - 3] = '\0';
			maxSpeed = atof(input);
			test.speed.value = maxSpeed;
			test.speed.value32 = htonl(test.speed.value32);
		}
	}	
		
	pcap->output.status = test;
	return 12 + strlen(pcap->output.status.zergName);
}

int getTypeNum(char * name)
{
	int sum = 0;
	
	for (int x = 0; x < strlen(name); x++)
	{
		sum += name[x];
	}
	switch(sum)
	{
		case 836:
			return 0;
		case 502:
			return 1;
		case 909:
			return 2;
		case 845:
			return 3;
		case 510:
			return 4;
		case 504:
			return 5;
		case 834:
			return 6;
		case 629:
			return 7;
		case 928:
			return 8;
		case 939:
			return 9;
		case 811:
			return 10;
		case 728:
			return 11;
		case 955:
			return 12;
		case 842:
			return 13;
		case 699:
			return 14;
		case 844:
			return 15;
		default:
			return -1;			
	}
}

unsigned long fillMsgPayload (struct zergPacket * pcap, FILE * fp, int filesize)
{
	int x, c, payloadLen;
	struct msgPayload test;
	
	payloadLen = filesize - ftell(fp);
	if ( (c = fgetc(fp)) == ' ')
	{
		;
	}
	else
	{
		ungetc(c, fp);
	}
	for (x = 0; x < payloadLen - 1; x++)
	{
		c = fgetc(fp);
		if ( c == '\n')
		{
			break;
		}
		test.message[x] = c;
	}
	pcap->output.data = test;
	return x;
}
