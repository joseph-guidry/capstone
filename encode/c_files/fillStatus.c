#include "encode.h"

unsigned long fillStatusPayload (struct zergPacket * pcap, FILE * fp)
{
	struct statusPayload test;
	char string[20], input[10];
	double maxSpeed;
	int hp, maxHp, armor, number; 
	
	fscanf(fp, "%s", input);
	strcpy(test.zergName, input);
	printf("%s \n", input);
	while(fscanf(fp, "%s%s", string, input) == 2)
	{
		printf("%s %s\n", string, input);
		for (unsigned int y = 0; y < strlen(string); y++)
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
				fprintf(stderr, "wrong type\n");
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
	
	for (unsigned int x = 0; x < strlen(name); x++)
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
		case 820:
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
