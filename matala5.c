#include <pcap.h>
#include <stdio.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <time.h>
#include <unistd.h>
#define SIZE_ETHERNET 14
struct ethheader
{
  u_char ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
  u_char ether_shost[ETHER_ADDR_LEN]; /* source host address */
  u_short ether_type;                 /* IP? ARP? RARP? etc */
};

struct ipheader
{
  unsigned char iph_ihl : 4,       // IP header length
      iph_ver : 4;                 // IP version
  unsigned char iph_tos;           // Type of service
  unsigned short int iph_len;      // IP Packet length (data + header)
  unsigned short int iph_ident;    // Identification
  unsigned short int iph_flag : 3, // Fragmentation flags
      iph_offset : 13;             // Flags offset
  unsigned char iph_ttl;           // Time to Live
  unsigned char iph_protocol;      // Protocol type
  unsigned short int iph_chksum;   // IP datagram checksum
  struct in_addr iph_sourceip;     // Source IP address
  struct in_addr iph_destip;       // Destination IP address
};

struct app_header
{
    uint32_t unixtime;
    uint16_t length;

    union
    {
        uint16_t flags;
        uint16_t _:3, c_flag:1, s_flag:1, t_flag:1, status:10;
    };
    
    uint16_t cache;
    uint16_t __;
};



void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{

FILE *file;
file=fopen("213861529_209321553.txt","a+");
if(file==NULL)
{
  printf("unable to create file");
}

  
  struct tcphdr *tcphdr;
  
  struct ethheader *eth = (struct ethheader *)packet;
  struct timeval start,finish;
  struct app_header *apphdr;

  
  time_t rawtime=header->ts.tv_sec;
  struct tm date;
  char buf[80];

  date=*localtime(&rawtime);
  strftime(buf,sizeof(buf),"%a %d-%m-%Y %H:%M:%S",&date);
  
  
  if (ntohs(eth->ether_type) == 0x0800)
  { // 0x0800 is IP type

    gettimeofday(&start,0);
    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
    tcphdr= (struct tcphdr*)(packet + ip->iph_ihl*4+ +sizeof(struct ethheader));
    apphdr= (struct app_header*)packet+sizeof(struct ethheader)+ip->iph_ihl*4+tcphdr->doff*4;
    /* determine protocol */
    switch (ip->iph_protocol)
    {
    case IPPROTO_TCP:

      printf("   Protocol: TCP\n");
      
    
    
      fprintf(file,"                        TCP header\n");
      fprintf(file,"**********************************************************************\n");
      fprintf(file,"           source_ip: %s\n", inet_ntoa(ip->iph_sourceip));
      fprintf(file,"           dest_ip: %s\n", inet_ntoa(ip->iph_destip));
      fprintf(file,"           source_port: %hu\n",ntohs(tcphdr->source));
      fprintf(file,"           dst_port: %hu\n",ntohs(tcphdr->dest));
      fprintf(file,"           timestap: %d (%s)\n",(apphdr->unixtime),buf);
      fprintf(file,"           total_length:%u \n",ntohs(apphdr->length));
      fprintf(file,"           cache_flag: %u \n",(apphdr->flags>>12) & 1);
      fprintf(file,"           step_flag: %u \n",(apphdr->flags>>11) & 1);
      fprintf(file,"           type_flag: %u \n",(apphdr->flags>>10) & 1);
      fprintf(file,"           status_code: %u \n",apphdr->status);
      fprintf(file,"           cache_control:%u \n",ntohs(apphdr->cache));
      fprintf(file,"           data: \n");
      fprintf(file,"**********************************************************************\n");
      fclose(file);
    
      return;
    case IPPROTO_UDP:
      printf("   Protocol: UDP\n");
      return;
    case IPPROTO_ICMP:
      printf("   Protocol: ICMP\n");
      return;
    default:
      printf("   Protocol: others\n");
      return;
    }
  }
}


// void got_packet(u_char *args, const struct pcap_pkthdr *header,
//                 const u_char *packet)
// {
//   printf("Got a packet\n");
// }



int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";
  bpf_u_int32 net;
  
  // Step 1: Open live pcap session on NIC with name eth3
  handle = pcap_open_live("lo", BUFSIZ, 1, 1000, errbuf);

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  pcap_setfilter(handle, &fp);

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle); // Close the handle

  

  return 0;


}