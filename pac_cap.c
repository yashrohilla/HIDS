#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <time.h>
#include <cs50.h>

#define MAXBYTE2CAPTURE 100
#define INT
typedef struct ip_address
{
  u_char byte1;
  u_char byte2;
  u_char byte3;
  u_char byte4;
}ip_address;

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

typedef struct icmp_header
{
  u_char type;
  u_char code;
  u_char crc;
  u_int RestofHeader;
  u_int data;
}icmp_header;


void
processPacket(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char *packet);

void
processPacket(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char *packet)
{
  //struct tm ltime;
  //char timestr[16];
  int *counter = (int *)arg;
  ip_header *ih;
  icmp_header *ich;
  u_int ip_len;
  time_t local_tv_sec;
  u_char typeofservice;
  //u_char int_head;
  int i;
  u_char protocol;
  u_char ich_type;
  int x;
  int temp;


    ih = (ip_header*)(packet + 18);   // Packet size according to ethernet wired packets
    //ip_len = (ih->ver_ihl & 0xf) * 4;

    ich = (icmp_header*)((u_char*)ih + ip_len); // note: earlier version ich = (icmp_header *)((u_char *)ih + ip_len); note: do not require instance for struct icmp
   // ich_type = (ich->type);
   // protocol = (ih->proto);

    
     // if(ich_type == 80)
      {
//	printf("\n%d\n", ich_type);
  //      printf("\n%d\n", protocol);
        printf("\n\npacket:%d\t",++(*counter));
        printf("len:%d\t\t", pkthdr->len);
        printf("%d.%d.%d.%d -> %d.%d.%d.%d\n",
            ih->saddr.byte1,
            ih->saddr.byte2,
            ih->saddr.byte3,
            ih->saddr.byte4,
            ih->daddr.byte1,
            ih->daddr.byte2,
            ih->daddr.byte3,
            ih->daddr.byte4);
 // printf("Packet Count: %d\n", ++(*counter));
 // printf("Received Packet Size: %d\n", pkthdr->len);
  printf("Payload:\n");
  for(i = 0; i < pkthdr->len; i++)
    if(isprint(packet[i]))
      printf("%c ", packet[i]);
      else
      printf(". ");

  if( (i % 16 == 0 && i != 0) || i==pkthdr->len - 1)
    printf("\n\n");
      }

}


int
main()
{
  int count = 0;
  pcap_t *descr = NULL;
  char errbuf[PCAP_ERRBUF_SIZE], *device = NULL;
  memset(errbuf, 0, PCAP_ERRBUF_SIZE);
  pcap_if_t *d;
  pcap_if_t *alldevs;
  ip_header *ih = 0;
  errbuf[0] = 0;

  printf("Enter the adapter to listen on\n");
  string dev = GetString();



  printf("Opening device %s\n", dev);

  descr = pcap_open_live(dev, MAXBYTE2CAPTURE, 0, 1000, errbuf);
  /* dev is the device, which I set to wlan0
   * MAXBYTE2CAPTURE is set in a fixed variable defined during the beginning.
   * Promiscuous mode; if set to 0 then only sniffing packets
   * destined for this host, if set to 1 then sniffing all packets in the network.
   * 1000 is the to_ms, amount of time to perform packet capture
   * errbuf is the buffer where the error message will be stored.
   */


  pcap_loop(descr, -1, processPacket, (u_char *)&count);
  // try different values of cnt (2nd variable).

  return 0;
}
