#include <stdio.h>

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
	uint8_t destMac[6];			//Ethernet Destination MAC address
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

struct zergPacket {
	struct filepcap fileHeader;				//pcap File Header structure
	struct headerpcap packetHeader;  		//pcap Packet Header structure
	struct etherFrame pcapFrame;			//pcap Ethernet Frame
	struct ipv4Header pcapIpv4;				//pcap IPv4 header
	struct udpHeader  pcapUdp;				//pcap UDP header
	struct zergHeader pcapZerg;				//custom Zerg Packet Header
};

struct msgPayload {
	char * message;
};

struct statusPayload {
	int32_t hitPoints;
	uint32_t maxHitPoints;
	uint32_t speed;
	char * zergName;
	
};

struct commandPayload {
	uint16_t command;
	uint16_t parameter1;
	uint32_t parameter2;
};

struct gpsDataPayload {
	uint64_t longitude;
	uint64_t latitude;
	uint32_t altitude;
	uint32_t bearing;
	uint32_t speed;
	uint32_t accuracy;
};

/*
union gps {
	double gpsCoord;
	struct makeDouble {
			uint64_t sign:1;
			uint64_t exponent:11;
			uint64_t mantissa:52;
		};
	};
*/
//Analyze the standard headers to determine the type of payload structure that will display the data

