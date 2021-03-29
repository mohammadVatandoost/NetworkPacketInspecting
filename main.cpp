#include <iostream>
#include<net/ethernet.h>
#include<netinet/ip_icmp.h>	
#include<netinet/udp.h>	
#include<netinet/tcp.h>	
#include<netinet/ip.h>
#include<sys/socket.h>
#include<arpa/inet.h> 
#include<string.h> 

extern "C" {
    #include <pcap.h>
}



using namespace std;

static int packetCount = 0;


void process_packet( const struct pcap_pkthdr *header, const u_char *buffer)
{
	int size= header->len;
	printf("-------------------------------------\n");

	/*Ethernet*/
	struct ethhdr *eth = (struct ethhdr *)buffer;
	printf("Ethernet: \n");
	printf( "   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
	printf( "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
	printf("   |-Protocol            : %u \n",(unsigned short)eth->h_proto);
	
	
	/*IP*/
	struct iphdr *iph=(struct iphdr *) (buffer + sizeof(struct ethhdr));
	int iphdrlen=iph->ihl*4;
	struct sockaddr_in source,dest;
	
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

	printf("\n");
	printf("IP Header\n");
	printf("   |-IP Version        : %d\n",(unsigned int)iph->version);
	printf("   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
	printf("   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
	printf("   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
	printf("   |-Identification    : %d\n",ntohs(iph->id));
	printf("   |-TTL      : %d\n",(unsigned int)iph->ttl);
	printf("   |-Protocol : %d\n",(unsigned int)iph->protocol);
	printf("   |-Checksum : %d\n",ntohs(iph->check));
	printf("   |-Source IP        : %s\n" , inet_ntoa(source.sin_addr) );
	printf("   |-Destination IP   : %s\n" , inet_ntoa(dest.sin_addr) );
	
	int header_size=0;
	
	/*ICMP*/
	if(iph->protocol==1)
	{
	
		struct icmphdr *icmph = (struct icmphdr *)(buffer + iphdrlen  + sizeof(struct ethhdr));
	
		header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;
	
	
			
		printf("\n");	
		printf("ICMP Header\n");
		printf("   |-Type : %d",(unsigned int)(icmph->type));
			
		if((unsigned int)(icmph->type) == 11)
		{
			printf("  (TTL Expired)\n");
		}
		else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
		{
			printf("  (ICMP Echo Reply)\n");
		}
	
		printf("   |-Code : %d\n",(unsigned int)(icmph->code));
		printf("   |-Checksum : %d\n",ntohs(icmph->checksum));
		printf("\n");
	
		
	}

	/*TCP*/
	if(iph->protocol==6)
	{


		struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));

		header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;

		printf("\n");
		printf("TCP Header\n");
		printf("   |-Source Port      : %u\n",ntohs(tcph->source));
		printf("   |-Destination Port : %u\n",ntohs(tcph->dest));
		printf("   |-Sequence Number    : %u\n",ntohl(tcph->seq));
		printf("   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
		printf("   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
		printf("   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
		printf("   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
		printf("   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
		printf("   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
		printf("   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
		printf("   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
		printf("   |-Window         : %d\n",ntohs(tcph->window));
		printf("   |-Checksum       : %d\n",ntohs(tcph->check));
		printf("   |-Urgent Pointer : %d\n",tcph->urg_ptr);
		printf("\n");
		printf("                        DATA Dump                         ");
		printf("\n");

	
	}

	/*UDP*/
	if(iph->protocol==17)
	{
	
		struct udphdr *udph = (struct udphdr*)(buffer + iphdrlen  + sizeof(struct ethhdr));
	
		header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
	
	
	
		printf("\nUDP Header\n");
		printf("   |-Source Port      : %d\n" , ntohs(udph->source));
		printf("   |-Destination Port : %d\n" , ntohs(udph->dest));
		printf("   |-UDP Length       : %d\n" , ntohs(udph->len));
		printf("   |-UDP Checksum     : %d\n" , ntohs(udph->check));
		
		printf("\n");
	}


	//printf("Data Payload\n");		
	//PrintData(Buffer + header_size , (Size - header_size) );

}

void packetHandler(u_char *useprData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
  process_packet(pkthdr,packet);
  cout << ++packetCount << " packet(s) captured" << endl;
  cout<<"Packet length:"<<pkthdr->len<<", time interval:" << pkthdr->ts.tv_sec <<endl;
//   cout<<"useprData:"<<useprData<<endl;
  cout<<"Packet:"<<string((char*)packet)<<endl;
}

int main() {
  char *dev;
  pcap_t *descr;
  char errbuf[PCAP_ERRBUF_SIZE];

  dev = pcap_lookupdev(errbuf);
  if (dev == NULL) {
      cout << "pcap_lookupdev() failed: " << errbuf << endl;
      return 1;
  }

  descr = pcap_open_live(dev, BUFSIZ, 0, -1, errbuf);
  if (descr == NULL) {
      cout << "pcap_open_live() failed: " << errbuf << endl;
      return 1;
  }

  if (pcap_loop(descr, 20, packetHandler, NULL) < 0) {
      cout << "pcap_loop() failed: " << pcap_geterr(descr);
      return 1;
  }

  cout << "capture finished" << endl;

  return 0;
}
