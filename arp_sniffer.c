#include <pcap.h>
#include <stdlib.h>
#include <string.h>

/* ARP Header, (assuming Ethernet+IPv4) */
#define ARP_REQUEST 1
#define ARP_REPLY 2

typedef struct ip_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

typedef struct arphdr
{
	u_int16_t htype;	//Hardware type
	u_int16_t ptype;	//Protocol type
	u_char hlen;		//Hardware address length
	u_char plen;		//Protocol Address length
	u_int16_t oper;		//Operation code
	ip_address saddr;
	ip_address daddr;
	u_char sha[6]; 		//Sender hardware address
	u_char spa[4];  	//Sender IP address
	u_char tha[6];		//Target hardware address
//	u_char tpa[4]; 		//Target IP address
}arphdr_t;

typedef struct ip_header
{
	u_char ver_ihl;
	u_char tos;
	u_char tlen;
	u_char identification;
	u_char flags_fo;
	u_char ttl;
	u_char proto;
	u_char crc;
	ip_address saddr;
	ip_address daddr;
	u_int op_pad;
}ip_header;

#define MAXBYTE2CAPTURE 2048

int
main(int argc, char *argv[])
{
	int i = 0;
	bpf_u_int32 netaddr = 0, mask = 0; //To store network address and netmask
	struct bpf_program filter;
	char errbuf[PCAP_ERRBUF_SIZE]; //Error Buffer
	pcap_t * descr = NULL; //Network interface handler
	struct pcap_pkthdr pkthdr; //Packet information, (timestamp, size...)
	const unsigned char *packet = NULL; // Received raw data
	arphdr_t *arpheader = NULL;	// Pointer to the arp header
	memset(errbuf, 0, PCAP_ERRBUF_SIZE);

	ip_header *ih;
	ih = (ip_header*)(packet + 22);

	if (argc != 2)
	{
		printf("USAGE: arpsniffer <interface>\n");
		exit(1);
	}

	descr = pcap_open_live(argv[1], MAXBYTE2CAPTURE, 0, 512, errbuf);

	// Look up info from the capture device
	pcap_lookupnet(argv[1], &netaddr, &mask, errbuf);

	// Compiles the filter expression into a BPF filterprogram
	pcap_compile(descr, &filter, "arp", 1, mask);

	// Load the filer program into the packet capture device
	pcap_setfilter(descr, &filter);

	while(1)
	{
		packet = pcap_next(descr, &pkthdr);
		arpheader = (struct arphdr *)(packet + 14); // Point to the ARP Header
//		printf("\n\nReceived Packet size: %d bytes\n", pkthdr.len);
//		printf("Hardware type: %s\n", (ntohs(arpheader->htype) == 1) ? "Ethernet" : "Unknown");
//		printf("Protocol type: %s\n", (ntohs(arpheader->ptype) == 1) ? "IPV4" : "Unknown");
//		printf("Operating: %s\n", (ntohs(arpheader->oper) == ARP_REQUEST) ? "ARP Request" : "ARP Reply");

		//If it is Ethernet and IPV4, print packet content
		if(ntohs(arpheader->htype) == 1 && ntohs(arpheader->ptype) == 0x0800)
		{
			printf("Sender MAC: ");
			for(i = 0; i < 6; i++)
				printf("%02X:", arpheader->sha[i]);
			printf("Sender IP: ");
	/*		printf("%d.%d.%d.%d\n",
					ih->saddr.byte1,
					ih->saddr.byte2,
					ih->saddr.byte3,
					ih->saddr.byte4);*/
			for(i = 0; i < 4; i++)
				printf("%d.", arpheader->spa[i]);
		/*	printf("Target MAC: ");
			for(i = 0; i < 6; i++)
				printf("%02X:", arpheader->tha[i]);
			printf("Target IP: ");
				printf("%d.", arpheader->tpa[i]);*/
			printf("\n");
		}
	}
return 0;
}
