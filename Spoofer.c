#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include<unistd.h>








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

/*ip header*/
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
/* ICMP Header  */
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

/******************************************************************
  Spoof an ICMP echo request using an arbitrary source IP Address
*******************************************************************/
void spoofIcmp ()
{
  char buffer[1500];

  memset(buffer, 0, 1500);

  /*********************************************************
     Step 1: Fill in the ICMP header.
   ********************************************************/
  struct icmpheader *icmp = (struct icmpheader *)(buffer + sizeof(struct ipheader));
  icmp->icmp_type = 8; // ICMP Type: 8 is request, 0 is reply.

  // Calculate the checksum for integrity
  icmp->icmp_chksum = 0;
  icmp->icmp_chksum = in_cksum((unsigned short *)icmp,
                               sizeof(struct icmpheader));

  /*********************************************************
     Step 2: Fill in the IP header.
   ********************************************************/
  struct ipheader *ip = (struct ipheader *)buffer;
  ip->iph_ver = 4;
  ip->iph_ihl = 5;
  ip->iph_ttl = 20;
  ip->iph_sourceip.s_addr = inet_addr("8.8.8.8");
  ip->iph_destip.s_addr = inet_addr("10.0.2.15");
  ip->iph_protocol = IPPROTO_ICMP;
  ip->iph_len = htons(sizeof(struct ipheader) +
                      sizeof(struct icmpheader));

  /*********************************************************
     Step 3: Finally, send the spoofed packet
   ********************************************************/
  send_raw_ip_packet(ip);
  

  
}

// /**********************************************
//   Constructing raw UDP packet
//  **********************************************/

#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>

/* UDP Header */
struct udpheader
{
  u_int16_t udp_sport; /* source port */
  u_int16_t udp_dport; /* destination port */
  u_int16_t udp_ulen;  /* udp length */
  u_int16_t udp_sum;   /* udp checksum */
};

/******************************************************************
  Spoof a UDP packet using an arbitrary source IP Address and port
*******************************************************************/
 void spoofudp()
{
  char buffer[1500];

  memset(buffer, 0, 1500);
  struct ipheader *ip = (struct ipheader *)buffer;
  struct udpheader *udp = (struct udpheader *)(buffer +
                                               sizeof(struct ipheader));

  /*********************************************************
     Step 1: Fill in the UDP data field.
   ********************************************************/
  char *data = buffer + sizeof(struct ipheader) +
               sizeof(struct udpheader);
  const char *msg = "Hello Server!\n";
  int data_len = strlen(msg);
  strncpy(data, msg, data_len);

  /*********************************************************
     Step 2: Fill in the UDP header.
   ********************************************************/
  udp->udp_sport = htons(12345);
  udp->udp_dport = htons(9090);
  udp->udp_ulen = htons(sizeof(struct udpheader) + data_len);
  udp->udp_sum = 0; /* Many OSes ignore this field, so we do not
                       calculate it. */

  /*********************************************************
     Step 3: Fill in the IP header.
   ********************************************************/
        ip->iph_ver = 4;
        ip->iph_ihl = 5;
        ip->iph_ttl = 20;
        ip->iph_sourceip.s_addr = inet_addr("1.2.3.4");
        ip->iph_destip.s_addr = inet_addr("10.2.2.5");
        ip->iph_protocol = IPPROTO_UDP; // The value is 17.   
        ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct udpheader) + data_len);

  /*********************************************************
     Step 4: Finally, send the spoofed packet
   ********************************************************/
  send_raw_ip_packet(ip);
}


#include <netinet/tcp.h>

/* Psuedo TCP header */
  struct pseudo_tcp
  {
    unsigned saddr, daddr;
    unsigned char mbz;
    unsigned char ptcl;
    unsigned short tcpl;
    struct tcphdr tcp;
    char payload[1500];
  };



 unsigned short calculate_tcp_checksum(struct ipheader * ip)
  {
    struct tcpheader *tcp = (struct tcpheader *)((u_char *)ip +
                                                 sizeof(struct ipheader));

    int tcp_len = ntohs(ip->iph_len) - sizeof(struct ipheader);

    /* pseudo tcp header for the checksum computation */
    struct pseudo_tcp p_tcp;
    memset(&p_tcp, 0x0, sizeof(struct pseudo_tcp));

    p_tcp.saddr = ip->iph_sourceip.s_addr;
    p_tcp.daddr = ip->iph_destip.s_addr;
    p_tcp.mbz = 0;
    p_tcp.ptcl = IPPROTO_TCP;
    p_tcp.tcpl = htons(tcp_len);
    memcpy(&p_tcp.tcp, tcp, tcp_len);

    return (unsigned short)in_cksum((unsigned short *)&p_tcp,
                                    tcp_len + 12);
  }

void spoofTcp()
{
  
  char buffer[1500];
  memset(buffer, 0, 1500);
  struct ipheader *ip = (struct ipheader *)buffer;
  struct tcphdr *tcp=(struct tcphdr*)(buffer+sizeof(struct ipheader));



  /*********************************************************
     Step 1: Fill in the TCP data field.
   ********************************************************/
  char *data = buffer + sizeof(struct ipheader) +
               sizeof(struct tcphdr);
  const char *msg = "Hello Server!\n";
  int data_len = strlen(msg);
  strncpy(data, msg, data_len);

/*********************************************************
      Step 2: Fill in the TCP header.
 ********************************************************/


    tcp->th_sport= htons(1234);
    tcp->th_dport = htons(5678);
    tcp->th_seq = htonl(0);
    tcp->th_ack = htonl(13);
    //tcp->th_off = 0x50;
    tcp->th_flags = 0x018;
    tcp->th_win = htons(2000);
    tcp->th_sum = 0;


  /*********************************************************
      Step 3: Fill in the IP header.
    ********************************************************/

    ip->iph_ver = 4;
    ip->iph_ihl = 5;
    ip->iph_ttl = 20;
    ip->iph_sourceip.s_addr = inet_addr("10.0.2.15");
    ip->iph_destip.s_addr = inet_addr("8.8.8.8");
    ip->iph_protocol = IPPROTO_TCP;
    ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct tcphdr) + data_len);

    tcp->th_sum = calculate_tcp_checksum(ip);
    /*********************************************************
     Step 4: Finally, send the spoofed packet
   ********************************************************/
  send_raw_ip_packet(ip);

}


/******************************************************************************/
int main()
{
  spoofIcmp();
  return 0;
}
