#include <stdio.h>

typedef union {						//Store floats and convert to binary
	double value;
	uint64_t value64;
} convertDouble;

typedef union {						//Store floats and convert to binary 
	float value;
	uint32_t value32;
} convertFloat;
\
/*
typdef union {
	struct ipv4Header ipv4;
	struct ipv6Header ipv6

} ipVersion;

*/
struct filepcap {
	uint32_t fileTypeID;			//*File Type ID
	uint16_t majorVersion;			//*Major Version
	uint16_t minorVersion;			//*Minor Version
	uint32_t gmtOffset;				//GMT Offset (Hours before/after GMT timezone)
	uint32_t accuracyDelta;			//Accuracy Delta
	uint32_t maxLengthCapture;		//Maximum length of a capture
	uint32_t linkLayerType;			//*Link Layer Type
};

struct headerpcap {
	uint32_t unixEpoch;				//UNIX Epoch -> start time of UNIX
	uint32_t microsec;				//microsecs from Epoch
	uint32_t dataCapture;			//Length of Caputured Data
	uint16_t trunPacketLen;			//Truncated packet length
};

struct etherFrame {
	uint8_t destMac[6];				//Ethernet Destination MAC address
	uint8_t srcMac[6];					
	uint16_t etherType;
};
	
struct ipv4Header {
	uint16_t ver_header;
	uint16_t totalIPhdrlen;
	uint16_t identification;
	uint16_t flags_frags;
	uint16_t nextProtocol;
	uint16_t ipChecksum;
	uint32_t srcAddroct1;				//Source IP Address
	uint32_t srcAddroct2;
	
};
/*
struct ipv6Header {
	uint32_t ver_class_flowLabel;
	uint32_t payloadLen_nxtHdr_HopLimit;
	uint8_t srcAddress[32];
	uint8_t destAddress[32];
};
*/
struct udpHeader {
	uint16_t sport;					//UDP Source Port
	uint16_t dport;					//UDP Destination Port
	uint16_t udpLen;
	uint16_t udpChecksum;
};

struct zergHeader {
	uint32_t ver_type_totalLen;					//Psychic Format version = 1
	uint16_t sourceID;
	uint16_t destID;
	uint32_t seqID;
};

struct msgPayload {
	char message[100];
};

struct statusPayload {
	uint32_t hitPoints;
	uint32_t maxHitPoints;
	convertFloat speed;
	char zergName[50];
};

struct commandPayload {
	uint16_t command;
	uint16_t parameter1;
	convertFloat parameter2; //CHANGE UNION CONVERT FLOAT????
};

struct gpsDataPayload {
	convertDouble longitude;
	convertDouble latitude;
	convertFloat altitude;
	convertFloat bearing;
	convertFloat speed;
	convertFloat accuracy;
};

typedef union {
	struct msgPayload data;
	struct statusPayload status;
	struct commandPayload command;
	struct gpsDataPayload gps;
} payload;

struct zergPacket {
	struct filepcap fileHeader;				//pcap File Header structure
	struct headerpcap packetHeader;  		//pcap Packet Header structure
	struct etherFrame pcapFrame;			//pcap Ethernet Frame
	struct ipv4Header pcapIpv4;				//pcap IPv4 header
	struct udpHeader  pcapUdp;				//pcap UDP header
	struct zergHeader pcapZerg;				//custom Zerg Packet Header
	payload output;							//Assign Type of Payload to structure.
};

unsigned long fillMsgPayload (struct zergPacket * pcap, FILE * fp, int filesize);
unsigned long fillStatusPayload (struct zergPacket * pcap, FILE * fp);
unsigned long fillGpsPayload (struct zergPacket * pcap, FILE * fp);
unsigned long fillCmdPayload( struct zergPacket * pcap, FILE * fp, char * command);
uint64_t swapLong( uint64_t x);
int getTypeNum(char * name);
uint32_t convertToBinary(int number, float decimal);
void buildPcapData (struct zergPacket * pcap);
void buildPcapPacket (struct zergPacket * pcap);
void buildEtherFrame (struct zergPacket * pcap);
void buildIpHeader (struct zergPacket * pcap);
void buildUdpHeader (struct zergPacket * pcap);
void buildZergHeader (struct zergPacket *pcap);
FILE * updateZergHeader (struct zergPacket * pcap, FILE * fp);